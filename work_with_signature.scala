package cacert.work_with_signature {

import java.security.cert.X509Certificate
import java.security.{PublicKey, Signature, PrivateKey}

trait work_with_signature {
  def sign_create(priv_key:PrivateKey, file_body_to_sign:Array[Byte],sign: Signature):Signature = {
    sign.initSign(priv_key)
    sign.update(file_body_to_sign)
    sign
  }

  def verify_sign(key:PublicKey, text_to_ver:Array[Byte], sign_text:Array[Byte]):Boolean = {
    val sig = Signature.getInstance("SHA1withRSA")
    sig.initVerify(key)
    sig.update(text_to_ver)
    if (sig.verify(sign_text))true
    else false
  }

  def verify_certificate(check_certif:X509Certificate, pub_key:PublicKey):Boolean = {
    val signature = check_certif.getSignature
    val DER_body = check_certif.getTBSCertificate
    verify_sign(pub_key,DER_body,signature)
  }
}
}
