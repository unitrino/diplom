package cacert.certificate_actor {

import java.security.cert.X509Certificate

import akka.actor.{Actor, ActorRef}
import akka.event.Logging
import cacert.CA.CA
import cacert.messages_for_certificate.reg_info
import cacert.user_actor.Sending_Data

case object Create_Req_CA
case object Create_CA
case object Req_For_Certif
case class Answ_Req_For_Certif(answ: X509Certificate)
case class Send_Req_For_Reg(flag: Boolean, req: reg_info, owner: ActorRef)
case class Send_Req_For_User_Reg(req: reg_info, owner: ActorRef,data:Sending_Data)
case object Create_Cert_For_User
case class Create_Top_Cert_For_User(cert: X509Certificate,data:Sending_Data)
case class Create_Top_Cert(cert: X509Certificate)
case class Get_Certif_Pack(cn_u: String, ou_u: String, path_to_files: String)
case class Answer_Certificates(user_cert: X509Certificate, ca_cert: X509Certificate, cn_u: String, ou_u: String, path_to_files: String)

class CA_Actor(top_level_ca: ActorRef, ca_obj: CA) extends Actor {
  val log = Logging(context.system.eventStream, self.path.name)
  def receive = {
    case Create_CA if top_level_ca == null => {
      ca_obj.create_self_certif()
      val ca_top_certif = ca_obj.ret_certif
      ca_obj.write_to_file(ca_top_certif.getEncoded, ca_obj.get_ca_dn_path + ".crt")
    }
    case Req_For_Certif => sender ! Answ_Req_For_Certif(ca_obj.get_ca_cert)
    case Create_Req_CA => {
      val reqq = reg_info(ca_obj.generate_req)
      top_level_ca ! Send_Req_For_Reg(true, reqq, self)
    }
    case s: Send_Req_For_Reg => {
      if (ca_obj.get_ca_cert != null) {
        s.owner ! Create_Top_Cert(ca_obj.create_certif_for_ca(s.flag, s.req))
      }
      else {
        self ! s
      }
    }
    case s: Send_Req_For_User_Reg => {
      if (ca_obj.get_ca_cert != null) {
        log.info("Starting registration user " + s.req.request_for_reg.getSubject.toString)
        val st = java.lang.System.currentTimeMillis()
        val cert_out: X509Certificate = if (ca_obj.get_ldap.is_elem_in_ldap(s.req.request_for_reg.getSubject.toString)) {
          log.info(s"VALUE EXISTS ${s.req.request_for_reg.getSubject.toString}")
          val arg = s.req.request_for_reg.getSubject.toString.split(',')
          val c1 = ca_obj.get_cert_pack(arg(0).substring(3), arg(1).substring(3))._1
          c1
        }
        else {
          log.info(s"VALUE IS NOT EXISTS ${s.req.request_for_reg.getSubject.toString}")
          ca_obj.create_certif_for_user(s.req)
        }
        s.owner ! Create_Top_Cert_For_User(cert_out, s.data)
        log.info("Ending of registration user " + s.req.request_for_reg.getSubject.toString + "\nTime (in ms): " + (java.lang.System.currentTimeMillis() - st).toString)
      }
      else {
        self ! s
      }
    }
    case s: Create_Top_Cert => {
      ca_obj.set_ca_cert(s.cert)
      ca_obj.write_to_file(ca_obj.get_ca_cert.getEncoded, ca_obj.get_ca_dn_path + ".crt")
    }
    case s: Get_Certif_Pack => {
      val (user, ca) = ca_obj.get_cert_pack(s.cn_u, s.ou_u)
      sender ! Answer_Certificates(user, ca, s.cn_u, s.ou_u, s.path_to_files)
    }
  }
}
}
