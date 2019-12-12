from playground.network.packet import PacketType
from playground.network.common.Protocol import StackingProtocolFactory
from playground.network.common.Protocol import StackingProtocol
from playground.network.common.Protocol import StackingTransport
from playground.network.packet.fieldtypes import STRING, UINT8, BUFFER, UINT16,UINT32, BOOL, LIST
from playground.network.packet.fieldtypes.attributes import Optional

from ..poop.protocol import POOP
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import logging
import random
import time
import os
import asyncio
import datetime
import binascii
import bisect
import uuid

# -------Definition Part---------
class CrapPacketType(PacketType):
    DEFINITION_IDENTIFIER = "crap"
    DEFINITION_VERSION = "1.0"

class HandshakePacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.handshakepacket"
    DEFINITION_VERSION = "1.0"
    NOT_STARTED = 0
    SUCCESS = 1
    ERROR = 2
    FIELDS = [
        ("status", UINT8),
        ("nonce", UINT32({Optional:True})),
        ("nonceSignature", BUFFER({Optional:True})),
        ("signature", BUFFER({Optional:True})),
        ("pk", BUFFER({Optional:True})),
        ("cert", BUFFER({Optional:True})),
        ("certChain", LIST(BUFFER, {Optional:True}))]

class DataPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.datapacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [("data", BUFFER),]

class ErrorPacket(CrapPacketType):
    DEFINITION_IDENTIFIER = "crap.errorpacket”"
    DEFINITION_VERSION = "1.0"
    FIELDS = [("message", STRING),]

class CRAPTransport(StackingTransport):
    def connect_protocol(self, protocol):
        self.protocol = protocol
    def write(self, data):
        self.protocol.send_data(data)
    def close(self):
        self.protocol.transport.close()

logger = logging.getLogger("playground.__connector__." + __name__)

# -----------Crap-----------
class CRAP(StackingProtocol):
    def __init__(self, mode):
        logger.debug("---------CrapTest Start: {}---------".format(mode))
        self.mode = mode
        self.deserializer = CrapPacketType.Deserializer()
        self.handshake = True
        #self.initenc = False
        logger.debug("---------CrapTest End: {}---------".format(self.mode))

    def process_data(self, packet):
        if self.mode == "client":
            decData = AESGCM(self.decA).decrypt(self.ivB, packet.data, None)
            self.ivB = (int.from_bytes(self.ivB, "big")+1).to_bytes(12,"big")
        elif self.mode == "server":
            decData = AESGCM(self.decB).decrypt(self.ivA, packet.data, None)
            self.ivA = (int.from_bytes(self.ivA, "big")+1).to_bytes(12,"big")
        self.higherProtocol().data_received(decData)

    def send_data(self, data):
        if self.mode == "client":
            encData = AESGCM(self.encA).encrypt(self.ivA, data, None)
            self.ivA = (int.from_bytes(self.ivA, "big")+1).to_bytes(12, "big")
        elif self.mode == "server":
            encData = AESGCM(self.encB).encrypt(self.ivB, data, None)
            self.ivB = (int.from_bytes(self.ivB, "big")+1).to_bytes(12, "big")
        new_packet = DataPacket(data = encData)
        self.transport.write(new_packet.__serialize__())

    def handshake_dealer(self, packet):
        if self.mode == "client":
            if packet.status == 1:
                self.certificate_2 = x509.load_pem_x509_certificate(packet.cert, default_backend())
                # verify the signature
                try:
                    logger.debug("------------Verification----------")
                    self.certificate_2.public_key().verify(packet.signature, packet.pk, padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())
                    self.certificate_2.public_key().verify(packet.nonceSignature, str(self.nonceA).encode("ASCII"), padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())

                    curve = self.certificate_2
                    curve_addr = self.certificate_2.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    for data in packet.certificate_chain:
                        c = x509.load_pem_x509_certificate(data, default_backend())
                        c.public_key().verify(curve.signature, curve.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
                        c_addr = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

                        for i in range(2):
                            if curve_addr[i] != cert_addr[i]:
                                raise Exception("**********unmatched*********")
                        curve = c
                    self.root_certificates.public_key().verify(curve.signature, curve.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
                    root_certificates_addr = self.root_certificates.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    if root_certificates_addr[0] != curve_addr [0]:
                        raise Exception("********unmatched**********")

                except Exception as error:
                    logger.debug("----------Handshake Handler Error: {}, {}--------------".format(self.mode, error))
                    logger.debug("----------Verification Failed------------")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return

                logger.debug("-----------Verification Succeed----------")

                self.public_key_2 = load_pem_public_key(packet.pk, backend=default_backend())
                self.shared_key = self.private1.exchange(ec.ECDH(), self.pubkB)

                # nonce 2
                self.nonce_2 = packet.nonce
                nonceSignature_1 = self.signing_key_1.sign(str(self.nonce_2).encode('ASCII'), padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())
                new_packet = HandshakePacket(status = 1, nonceSignature = nonceSignature_!)
                self.transport.write(new_packet.__serialize__())

                # generate keys and transfer to a higher protocol
                digest = hashes.Hash(hashes.SHA256(), backend = default_backend()).update(self.shared_key)
                hash1 = digest.finalize()
                self.ivA = hash1[:12]
                self.ivB = hash1[12:]
                digest = hashes.Hash(hashes.SHA256(), backend = default_backend()).update(hash1)
                hash2 = digest.finalize()
                self.encA = hash2[:16]
                digest = hashes.Hash(hashes.SHA256(), backend = default_backend()).update(hash2) 
                hash3 = digest.finalize()
                self.decA = hash3[:16]

                self.handshake = False
                self.higherProtocol().connection_made(self.high_transport)

                logger.debug("-----------Client: Sent Second Packet--------")
                print("------------Client: Handshake Success----------")
            else:
                error_packet = HandshakePacket(status=2)
                self.transport.write(error_packet.__serialize__())
                self.transport.close()

        if self.mode == "server":
            if packet.status == 0:
                logger.debug("---------Server: Start Sending Packet---------")

                self.root_certificates = cryptography.x509.load_pem_x509_certificate(open('/home/student_20194/.playground/connectors/crap/20194_root.cert', 'rb').read(), default_backend())
                self.team_certificates = cryptography.x509.load_pem_x509_certificate(open('/home/student_20194/.playground/connectors/crap/csr_team4_signed.cert', 'rb').read(), default_backend())

                self.certificate_1 = x509.load_pem_x509_certificate(packet.cert, default_backend())

                # verify the signature
                try:
                    logger.debug(packet.pk.decode("ASCII"))
                    self.certificate_1.public_key().verify(packet.signature, packet.pk, padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())

                    curve = self.certificate_1
                    curve_addr = cert_1_address
                    for data in packet.certChain:
                        c = x509.load_pem_x509_certificate(data, default_backend())
                        c.public_key().verify(curve.signature, curve.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
                        c_addr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        for i in range(2):
                            if curve_addr[i] != c_addr[i]:
                                raise Exception("********unmatched*********")
                        curve = c
                    self.root_certificates.public_key().verify(curve.signature, curve.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
                    certificates_r_addr = self.root_certificates.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                    if certificates_r_addr[0] != curve_addr [0]:
                        raise Exception("unmatched perfix")

                except Exception as error:
                    logger.debug("---------Crap Handshake Handler Error: {}, {}--------".format(self.mode, error))
                    logger.debug("---------Verification Failed---------")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return

                logger.debug("-----------Verification Succeed-----------")
                # create a secret key, a public key and a signing key
                self.private_key_2 = ec.generate_private_key(ec.SECP384R1(), default_backend())
                self.public_key_2 = self.private_key_2.public_key()
                self.signing_key_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

                # get the shared key
                self.public_key_1 = load_pem_public_key(packet.pk, backend=default_backend())
                self.shared_key = self.private_key_2.exchange(ec.ECDH(), self.public_key_1)

                # create a certification
                self.root_certificates = cryptography.x509.load_pem_x509_certificate(open('/home/student_20194/.playground/connectors/crap/20194_root.cert', 'rb').read(), default_backend())
                self.team_certificates = cryptography.x509.load_pem_x509_certificate(open('/home/student_20194/.playground/connectors/crap/csr_team4_signed.cert', 'rb').read(), default_backend())
                self.private_key_team = serialization.load_pem_private_key(open('/home/student_20194/.playground/connectors/crap/key_team4.pem', 'rb').read(),password=b'passphrase',backend=default_backend())
                
                subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"), x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"), x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Team 4"), x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4"),])
                self.certB = x509.CertificateBuilder().subject_name(subject).issuer_name(self.certificates_team.subject).public_key(self.signkB.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"20194.4.4.4")]),critical=False,).sign(self.private_team, hashes.SHA256(), default_backend())
                certB_bytes = self.certB.public_bytes(Encoding.PEM)

                self.certChain = [team_cert]
                # create a signature for the public key
                pubkB_bytes = self.pubkB.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                self.sigB = self.signkB.sign(pubkB_bytes, padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())

                self.nonce_1 = packet.nonce
                self.nonce_2_Signature = self.signing_2.sign(str(self.nonce_1).encode('ASCII'), padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())

                self.nonce_2 = random.randint(0,2**32)
                new_packet = HandshakePacket(status = 1,nonce = self.nonce_2, nonceSignature = self.nonce_2_Signature, pk = public2_bytes, signature = self.signature_2, cert = cert2_bytes, certChain = self.certificate_chain)
                self.transport.write(new_packet.__serialize__())
                logger.debug("-----------Server: Sent Packet----------")


            elif packet.status == 1:
                logger.debug("-----------Server: Start Sending Packet----------")
                try:
                    logger.debug("------------Verification------------")
                    self.certificates_1.public_key().verify(packet.nonceSignature, str(self.nonce_2).encode("ASCII"), padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH),hashes.SHA256())
                except Exception as error:
                    logger.debug("---------------Handshake Handler Error: {}, {}--------------".format(self.mode, error))
                    logger.debug("------------Verification Failed------------")
                    error_packet = HandshakePacket(status=2)
                    self.transport.write(error_packet.__serialize__())
                    self.transport.close()
                    return
                logger.debug("------------Verification Succeed-----------")

                # generate keys and transfer to a higher protocol
                digest = hashes.Hash(hashes.SHA256(), backend = default_backend())
                digest.update(self.shared_key)
                hash1 = digest.finalize()
                self.ivA = hash1[0:12]
                self.ivB = hash1[12:24]
                digest = hashes.Hash(hashes.SHA256(), backend = default_backend()).update(hash1)
                hash2 = digest.finalize()
                self.decB = hash2[0:16]
                digest = hashes.Hash(hashes.SHA256(), backend = default_backend()).update(hash2)
                hash3 = digest.finalize()
                self.encB = hash3[0:16]

                logger.debug(self.ivA)
                logger.debug(self.ivB)

                self.handshake = False
                self.higherProtocol().connection_made(self.high_transport)

                logger.debug("-------------Server: Stop Sending Packet-----------")


    def connection_made(self,transport):
        logger.debug("----------Connection Made: {}----------".format(self.mode))
        self.transport = transport
        self.high_transport = CRAPTransport(transport)
        self.high_transport.connect_protocol(self)

        if self.mode == "client":
            # create a secret key, a public key and a signing key
            self.private_key_1 = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.public_key_1 = self.private_key_1.public_key()
            self.signing_key_1 = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend())

            # get the certificates
            self.root_certificates = cryptography.x509.load_pem_x509_certificate(open('/home/student_20194/.playground/connectors/crap/20194_root.cert', 'rb').read(), default_backend())            
            self.team_certificates = cryptography.x509.load_pem_x509_certificate(open('/home/student_20194/.playground/connectors/crap/csr_team4_signed.cert', 'rb').read(), default_backend())
            self.private_key_team = serialization.load_pem_private_key(open('/home/student_20194/.playground/connectors/crap/key_team4.pem', 'rb').read(),backend=default_backend(),password=b'passphrase')

            logger.debug("----------Client Started Sending Packet----------")

            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"20194.4.4.4"),])
            self.certificate_1 = x509.CertificateBuilder().subject_name(subject).issuer_name(self.team_certificates.subject).public_key(self.signing_key_1.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"20194.4.4.4")]),critical=False,).sign(self.private_key_team, hashes.SHA256(), default_backend())
            cert1_bytes = self.certificate_1.public_bytes(Encoding.PEM)

            # create a signature for the public key
            public1_bytes = self.public_key_1.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            self.signature_1 = self.signing_key_1.sign(public1_bytes, padding.PSS(mgf = padding.MGF1(hashes.SHA256()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA256())

            # transport the packet
            self.certificate_chain = [open('/home/student_20194/.playground/connectors/crap/csr_team4_signed.cert', 'rb').read()]
            self.nonce_1 = random.randint(0, 2**32)
            new_packet = HandshakePacket(status = 0, nonce = self.nonce_1, pk = public1_bytes, signature = self.signature_1, cert = cert1_bytes, certChain = self.certificate_chain)
            self.transport.write(new_packet.__serialize__())
            logger.debug("----------Client Stop Sending Packet----------")

        logger.debug("------------Connection Made End: {}-----------".format(self.mode))

    def data_received(self, buffer):
        logger.debug("------------Data received-----------")
        self.deserializer.update(buffer)
        for p in self.deserializer.nextPackets():
            print(p)
            if isinstance(p, HandshakePacket):
                if self.handshake:
                    self.handshake_dealer(p)
            elif isinstance(p, DataPacket):
                if not self.handshake:
                    self.process_data(p)
            elif isinstance(p, ErrorPacket):
                logger.debug(p.message)
                logger.debug("-------------Packet Error------------")

    def connection_lost(self, exc):
        logger.debug("--------------Connection Lost------------")
        self.higherProtocol().connection_lost(exc)

SecureClientFactory = StackingProtocolFactory.CreateFactoryType(lambda : POOP(mode="client"), lambda : CRAP(mode="client"))
SecureServerFactory = StackingProtocolFactory.CreateFactoryType(lambda : POOP(mode="server"), lambda : CRAP(mode="server"))    

