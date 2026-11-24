/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.server;

import org.apache.kerby.kerberos.kerb.KrbCodec;
import org.apache.kerby.kerberos.kerb.KrbErrorCode;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.common.KrbUtil;
import org.apache.kerby.kerberos.kerb.identity.KrbIdentity;
import org.apache.kerby.kerberos.kerb.identity.backend.BackendConfig;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;
import org.apache.kerby.kerberos.kerb.server.preauth.PreauthHandler;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.KrbError;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessage;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.kdc.AsReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcOptions;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReq;
import org.apache.kerby.kerberos.kerb.type.kdc.KdcReqBody;
import org.apache.kerby.kerberos.kerb.type.kdc.TgsReq;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataEntry;
import org.apache.kerby.kerberos.kerb.type.pa.PaDataType;
import org.apache.kerby.kerberos.kerb.type.pa.PaEncTsEnc;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the KDC only treats a request as pre-authenticated when one of
 * the supplied preauth data entries was actually verified, and does not issue
 * tickets for requests whose preauth data is unknown or could not be verified.
 */
public class KdcPreauthVerificationTest {
    private static final String REALM = "EXAMPLE.COM";
    private static final String CLIENT = "alice@" + REALM;
    private static final String SERVICE = "test-service/localhost@" + REALM;
    private static final String PASSWORD = "alice-password";

    private KdcHandler kdcHandler;
    private EncryptionKey clientKey;
    private EncryptionKey wrongClientKey;

    @Before
    public void setUp() throws KrbException {
        KdcConfig kdcConfig = new KdcConfig();
        BackendConfig backendConfig = new BackendConfig();
        KdcSetting kdcSetting = new KdcSetting(kdcConfig, backendConfig);
        assertThat(kdcSetting.getKdcRealm()).isEqualTo(REALM);
        assertThat(kdcConfig.isPreauthRequired()).isTrue();

        List<EncryptionType> encTypes = kdcConfig.getEncryptionTypes();
        assertThat(encTypes).contains(EncryptionType.AES128_CTS_HMAC_SHA1_96);

        IdentityBackend backend = KdcUtil.getBackend(backendConfig);

        String tgsName = KrbUtil.makeTgsPrincipal(REALM).getName();
        KrbIdentity tgsIdentity = new KrbIdentity(tgsName);
        tgsIdentity.addKeys(EncryptionUtil.generateKeys(encTypes));
        backend.addIdentity(tgsIdentity);

        KrbIdentity serviceIdentity = new KrbIdentity(SERVICE);
        serviceIdentity.addKeys(EncryptionUtil.generateKeys(encTypes));
        backend.addIdentity(serviceIdentity);

        KrbIdentity clientIdentity = new KrbIdentity(CLIENT);
        clientIdentity.addKeys(EncryptionUtil.generateKeys(CLIENT, PASSWORD, encTypes));
        backend.addIdentity(clientIdentity);
        clientKey = clientIdentity.getKey(EncryptionType.AES128_CTS_HMAC_SHA1_96);

        wrongClientKey = EncryptionUtil.generateKeys(CLIENT, "wrong-password",
            Collections.singletonList(EncryptionType.AES128_CTS_HMAC_SHA1_96)).get(0);

        KdcContext kdcContext = new KdcContext(kdcSetting);
        kdcContext.setIdentityService(backend);
        PreauthHandler preauthHandler = new PreauthHandler();
        preauthHandler.init();
        kdcContext.setPreauthHandler(preauthHandler);

        kdcHandler = new KdcHandler(kdcContext);
    }

    @Test
    public void testAsReqWithoutPaDataIsRejected() throws Exception {
        AsReq asReq = makeAsReq();

        assertPreauthRequired(process(asReq));
    }

    @Test
    public void testAsReqWithOnlyUnknownPaDataIsRejected() throws Exception {
        // PA-PAC-REQUEST has no KDC preauth plugin, so it can never prove
        // knowledge of the client key. It must not satisfy required preauth.
        AsReq asReq = makeAsReq(new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {0x30, 0x00}));

        assertPreauthRequired(process(asReq));
    }

    @Test
    public void testAsReqWithOnlyUnverifiedTokenPaDataIsRejected() throws Exception {
        // The token plugin handles TOKEN_CHALLENGE but reports it as not verified.
        AsReq asReq = makeAsReq(new PaDataEntry(PaDataType.TOKEN_CHALLENGE, "challenge".getBytes()));

        assertPreauthRequired(process(asReq));
    }

    @Test
    public void testAsReqWithOnlyClientSentPkAsRepIsRejected() throws Exception {
        // A PK_AS_REP is a KDC reply type; a client-sent one carries nothing to verify.
        AsReq asReq = makeAsReq(new PaDataEntry(PaDataType.PK_AS_REP, "bogus".getBytes()));

        assertPreauthRequired(process(asReq));
    }

    @Test
    public void testAsReqWithSeveralUnverifiedPaDataIsRejected() throws Exception {
        AsReq asReq = makeAsReq(
            new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {0x30, 0x00}),
            new PaDataEntry(PaDataType.TOKEN_CHALLENGE, "challenge".getBytes()),
            new PaDataEntry(PaDataType.PK_AS_REP, "bogus".getBytes()));

        assertPreauthRequired(process(asReq));
    }

    @Test
    public void testAsReqWithWrongEncTimestampIsRejected() throws Exception {
        AsReq asReq = makeAsReq(makeEncTsEntry(wrongClientKey));

        KrbMessage reply = process(asReq);
        assertThat(reply.getMsgType()).isEqualTo(KrbMessageType.KRB_ERROR);
    }

    @Test
    public void testAsReqWithValidEncTimestampIsAccepted() throws Exception {
        AsReq asReq = makeAsReq(makeEncTsEntry(clientKey));

        KrbMessage reply = process(asReq);
        assertThat(reply.getMsgType()).isEqualTo(KrbMessageType.AS_REP);
    }

    @Test
    public void testAsReqWithUnknownAndValidEncTimestampIsAccepted() throws Exception {
        AsReq asReq = makeAsReq(
            new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {0x30, 0x00}),
            makeEncTsEntry(clientKey));

        KrbMessage reply = process(asReq);
        assertThat(reply.getMsgType()).isEqualTo(KrbMessageType.AS_REP);
    }

    @Test
    public void testTgsReqWithoutPaDataIsRejected() throws Exception {
        TgsReq tgsReq = makeTgsReq();

        assertPreauthRequired(process(tgsReq));
    }

    @Test
    public void testTgsReqWithOnlyUnknownPaDataIsRejected() throws Exception {
        // A TGS-REQ without a PA-TGS-REQ (AP-REQ) entry must not be treated as authenticated.
        TgsReq tgsReq = makeTgsReq(new PaDataEntry(PaDataType.PAC_REQUEST, new byte[] {0x30, 0x00}));

        assertPreauthRequired(process(tgsReq));
    }

    private void assertPreauthRequired(KrbMessage reply) {
        assertThat(reply.getMsgType()).isEqualTo(KrbMessageType.KRB_ERROR);
        assertThat(((KrbError) reply).getErrorCode()).isEqualTo(KrbErrorCode.KDC_ERR_PREAUTH_REQUIRED);
    }

    private KrbMessage process(KdcReq kdcReq) throws KrbException, IOException {
        ByteBuffer request = ByteBuffer.wrap(KrbCodec.encode(kdcReq));
        ByteBuffer response = kdcHandler.handleMessage(request, false,
            InetAddress.getByName("127.0.0.1"));
        return KrbCodec.decodeMessage(response);
    }

    private AsReq makeAsReq(PaDataEntry... paDataEntries) {
        AsReq asReq = new AsReq();
        asReq.setReqBody(makeReqBody(new PrincipalName(CLIENT), KrbUtil.makeTgsPrincipal(REALM)));
        for (PaDataEntry paDataEntry : paDataEntries) {
            asReq.addPaData(paDataEntry);
        }
        return asReq;
    }

    private TgsReq makeTgsReq(PaDataEntry... paDataEntries) {
        TgsReq tgsReq = new TgsReq();
        tgsReq.setReqBody(makeReqBody(new PrincipalName(CLIENT), new PrincipalName(SERVICE)));
        for (PaDataEntry paDataEntry : paDataEntries) {
            tgsReq.addPaData(paDataEntry);
        }
        return tgsReq;
    }

    private KdcReqBody makeReqBody(PrincipalName clientPrincipal, PrincipalName serverPrincipal) {
        long now = System.currentTimeMillis();

        KdcReqBody body = new KdcReqBody();
        body.setKdcOptions(new KdcOptions());
        body.setCname(clientPrincipal);
        body.setRealm(REALM);
        body.setSname(serverPrincipal);
        body.setFrom(new KerberosTime(now));
        body.setTill(new KerberosTime(now + 24L * 60 * 60 * 1000));
        body.setNonce(12345);
        body.setEtypes(Collections.singletonList(EncryptionType.AES128_CTS_HMAC_SHA1_96));
        return body;
    }

    private PaDataEntry makeEncTsEntry(EncryptionKey key) throws KrbException {
        PaEncTsEnc paTs = new PaEncTsEnc();
        paTs.setPaTimestamp(KerberosTime.now());
        EncryptedData encryptedTs = EncryptionUtil.seal(paTs, key, KeyUsage.AS_REQ_PA_ENC_TS);
        return new PaDataEntry(PaDataType.ENC_TIMESTAMP, KrbCodec.encode(encryptedTs));
    }
}
