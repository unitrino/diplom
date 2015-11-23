package cacert.CA {

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.Security
import java.security.cert.{CertificateFactory, X509Certificate}
import java.util.Date

import cacert.ldap_db.LDAP_db
import cacert.messages_for_certificate.{reg_info, file_wrapper}
import cacert.read_write_files.read_write_files
import cacert.work_with_certificate.work_with_certificate
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.{X509ExtensionUtils, X509v3CertificateBuilder}
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509ContentVerifierProviderBuilder}
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.slf4j.LoggerFactory

class CA(ca_name: String, level: String, ldap_login: String, ldap_pass: String) extends work_with_certificate with read_write_files {
  import com.typesafe.scalalogging._
  private val logger = Logger(LoggerFactory.getLogger(this.getClass))
  private val key_pair = generate_RSA_KeyPair()
  private val ca_private_key = key_pair.getPrivate()
  private val ca_public_key = key_pair.getPublic()
  private val ca_dn_path = "cn=" + ca_name + ",ou=" + level
  private val algo = "SHA1withRSA"
  private var ca_cert: X509Certificate = null
  private val ldap = new LDAP_db(ldap_login, ldap_pass)

  def get_ldap = ldap

  def get_ca_dn_path = ca_dn_path

  def get_ca_cert = ca_cert

  def set_ca_cert(crt:X509Certificate) = ca_cert = crt

  def get_cert_pack(user_cn_path: String, user_ou_path: String): (X509Certificate, X509Certificate) = {
    val out_path = "cn=" + user_cn_path + ",ou=" + user_ou_path
    val bytes_cert = ldap.extract_data(out_path).file_data
    val cf = CertificateFactory.getInstance("X.509", "BC")
    val byte_stream = new ByteArrayInputStream(bytes_cert)
    val cert = cf.generateCertificate(byte_stream).asInstanceOf[X509Certificate]
    (cert, ca_cert)
  }

  def create_self_certif() {
    ca_cert = generate_v1_certif(BigInteger.valueOf(System.currentTimeMillis()),
      ca_dn_path, new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + 100000000), key_pair, algo)
    ldap.add_with_check(ca_dn_path, file_wrapper(ca_cert.getEncoded))
  }

  def ret_certif = ca_cert

  def create_certif_for_user(req_data: reg_info) = {
    //    println("Checking request consintancy")
    val zz = new JcaX509ContentVerifierProviderBuilder().build(req_data.request_for_reg.getSubjectPublicKeyInfo)
    //    println(req_data.request_for_reg.isSignatureValid(zz))
    logger.info(s"CHECK REQUEST CONSIST ${req_data.request_for_reg.getSubject} is - " +
      s"${req_data.request_for_reg.isSignatureValid(zz)}")

    val serial_numb = BigInteger.valueOf(System.currentTimeMillis())
    val data_start = new Date(System.currentTimeMillis())
    val data_end = new Date(System.currentTimeMillis() + 100000000)

    val out_sing_cert = generate_v3_certif(algo, ca_cert, req_data.request_for_reg, serial_numb, data_start, data_end, false)
    ldap.add_with_check(req_data.request_for_reg.getSubject.toString, file_wrapper(out_sing_cert.getEncoded))
    out_sing_cert
  }

  def create_certif_for_ca(f: Boolean, req_data: reg_info): X509Certificate = {
    val zz = new JcaX509ContentVerifierProviderBuilder().build(req_data.request_for_reg.getSubjectPublicKeyInfo)
    //println(req_data.request_for_reg.isSignatureValid(zz))
    logger.info(s"CHECK REQUEST CONSIST ${req_data.request_for_reg.getSubject} is - " +
      s"${req_data.request_for_reg.isSignatureValid(zz)}")
    val serial_numb = BigInteger.valueOf(System.currentTimeMillis())
    val data_start = new Date(System.currentTimeMillis())
    val data_end = new Date(System.currentTimeMillis() + 100000000)

    val out_sing_cert = generate_v3_certif(algo, ca_cert, req_data.request_for_reg, serial_numb, data_start, data_end, f)
    ldap.add_with_check(req_data.request_for_reg.getSubject.toString, file_wrapper(out_sing_cert.getEncoded))
    out_sing_cert
  }

  def generate_v3_certif(algo: String, higher_certif: X509Certificate, request: PKCS10CertificationRequest,
                         serial_numb: BigInteger, d_s: Date, d_e: Date, flag_ca: Boolean): X509Certificate = {

    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())

    val subjectPublicKeyInfo: SubjectPublicKeyInfo = request.getSubjectPublicKeyInfo

    val out_certif = new X509v3CertificateBuilder(new X500Name(higher_certif.getSubjectDN.toString),
      serial_numb, d_s, d_e,
      request.getSubject,
      subjectPublicKeyInfo)

    val digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1))
    val x509ExtensionUtils = new X509ExtensionUtils(digCalc)
    out_certif.addExtension(Extension.authorityKeyIdentifier, true, x509ExtensionUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo))
    if (flag_ca) {
      val ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature)
      out_certif.addExtension(Extension.keyUsage, false, ku)
      out_certif.addExtension(Extension.basicConstraints, false, new BasicConstraints(true))
      out_certif.addExtension(Extension.subjectKeyIdentifier, true, x509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo))
    }
    else {
      out_certif.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
      out_certif.addExtension(Extension.subjectKeyIdentifier, true, x509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo))
    }
    val signGen = new JcaContentSignerBuilder(algo).build(ca_private_key)
    val cert_holder = out_certif.build(signGen)
    new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert_holder)
  }

  def generate_req: PKCS10CertificationRequest = {
    val req = generate_request(algo, ca_dn_path, key_pair)
    req
  }
}

}
