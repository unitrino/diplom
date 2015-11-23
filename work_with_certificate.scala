package cacert.work_with_certificate {

import java.io.{FileOutputStream, FileInputStream, File}
import java.math.BigInteger
import java.security.{Security, SecureRandom, KeyPairGenerator, KeyPair}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.util.Date

import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder

trait work_with_certificate {
  def read_certif_from_file(path_to: String): X509Certificate = {
    val ff = new File(path_to)
    val fis = new FileInputStream(ff)
    val cf = CertificateFactory.getInstance("X.509")
    val cert = cf.generateCertificate(fis).asInstanceOf[X509Certificate]
    cert
  }

  def write_certif_to_file(data: X509Certificate, path_to: String) {
    val file = new File(path_to+".crt")
    val fs = new FileOutputStream(file);
    fs.write(data.getEncoded)
    fs.flush()
    println("END WRITING")
  }

  def generate_RSA_KeyPair(): KeyPair = {
    val kpGen = KeyPairGenerator.getInstance("RSA")
    kpGen.initialize(1024, new SecureRandom())
    return kpGen.generateKeyPair()
  }

  def generate_request(algorithm: String, dn_path: String, pair: KeyPair): PKCS10CertificationRequest = {
    val signGen = new JcaContentSignerBuilder(algorithm).build(pair.getPrivate)
    val subject = new X500Name(dn_path)
    val builder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic)
    val csr = builder.build(signGen)
    csr
  }

  def generate_v1_certif(serial_numb: BigInteger, dn_path: String,
                         d_s: Date, d_e: Date, pair: KeyPair, algo: String): X509Certificate = {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
    val encoded = pair.getPublic.getEncoded
    val subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded))
    val out_certif = new X509v3CertificateBuilder(new X500Name(dn_path), serial_numb, d_s, d_e, new X500Name(dn_path), subjectPublicKeyInfo)
    val signGen = new JcaContentSignerBuilder(algo).build(pair.getPrivate)
    val cert_holder = out_certif.build(signGen)
    new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert_holder)
  }

}
}
