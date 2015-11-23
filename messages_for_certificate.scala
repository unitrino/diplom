package cacert.messages_for_certificate {

import java.security.Signature
import java.security.cert.X509Certificate

import org.bouncycastle.pkcs.PKCS10CertificationRequest

case class reg_info(request_for_reg:PKCS10CertificationRequest)
case class out_certif_pack(ca_cert:X509Certificate,user_certif:X509Certificate)
case class file_with_sing(file_body:Array[Byte],sign:Signature)
case class req_for_certif_pack(user_dn:String)
case class file_wrapper(file_data:Array[Byte])
}
