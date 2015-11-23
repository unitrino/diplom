package cacert.user_actor {

import java.io.{FileNotFoundException, File}
import akka.actor.{Actor, ActorRef}
import akka.event.Logging
import cacert.certificate_actor.{Get_Certif_Pack, Answer_Certificates, Create_Top_Cert_For_User, Send_Req_For_User_Reg}
import cacert.messages_for_certificate.file_with_sing
import cacert.read_write_files.read_write_files
import cacert.user.user

case class Sending_Data(send_to: ActorRef, path_to_file: String, out_name_file: String)
case class Create_Req_User(data:Sending_Data)
case class Create_Sing(data:Sending_Data)
case class Verify_Certificate(cn_user: String, ou_user: String)
case class Data_for_verify(cn_user: String, ou_user: String, dat: file_with_sing, path_to_file_send: String, out_name_file: String)

class User_Actor(top_level_ca: ActorRef, u: user) extends Actor with read_write_files{
    private val log = Logging(context.system.eventStream, self.path.name)
    override def preStart = {log.info("User Start Working");u.start_work()}
    def receive = {
      case s: Create_Req_User => {
        log.info("Start create request")
        val st = java.lang.System.currentTimeMillis()
        val out_folder = u.ret_folder_path._2
        copy_files(s.data.path_to_file,out_folder + "/" + new File(s.data.path_to_file).getName)
        val reqq = u.send_req_for_registration()
        log.info("End of creating request\nTime (in ms): " + (java.lang.System.currentTimeMillis()-st).toString)
        top_level_ca ! Send_Req_For_User_Reg(reqq, self,s.data)
      }
      case s:Create_Top_Cert_For_User => {
        val cert_path_users = u.ret_folder_path._4
        write_to_file(s.cert.getEncoded,cert_path_users + "/" + u.usr_cn + ".crt")
        log.info(s"REGISTRATION COMPLETE for ${s.cert.getSubjectDN}")
        self ! Create_Sing(s.data)
      }
      case s:Create_Sing => {
        try {
          log.info("Start of creating singature")
          val st = java.lang.System.currentTimeMillis()
          val signat = u.sign_document(s.data.path_to_file)
          val dat = file_with_sing(u.read_from_file(s.data.path_to_file), signat)
          log.info("End of creating singature\nTime (in ms): " + (java.lang.System.currentTimeMillis()-st).toString)
          s.data.send_to ! Data_for_verify(u.usr_cn, u.usr_ou, dat, s.data.path_to_file, s.data.out_name_file)
        }
        catch {
          case _:FileNotFoundException => println(s"Incorrect file path to send ${s.data.path_to_file}")
        }
      }
      case s: Answer_Certificates => {
        log.info("Start verifying files")
        val st = java.lang.System.currentTimeMillis()
        val (_,_,cert_path_ca,cert_path_users) = u.ret_folder_path
        write_to_file(s.ca_cert.getEncoded,cert_path_ca + "/ca_cert.crt")
        write_to_file(s.user_cert.getEncoded,cert_path_users + "/" + s.cn_u + ".crt")
        log.info(s"Verify certificate to ${u.usr_cn}" +
          s" from ${s.cn_u} is ${u.verify_certificate(s.user_cert, s.ca_cert.getPublicKey)}"
        )
        val (doc_p, sign_p) = u.get_doc_and_sign_paths(s.path_to_files)

        log.info(s"Verify document ${doc_p} to ${u.usr_cn}" +
          s" from ${s.cn_u} is ${u.verify_sign(s.user_cert.getPublicKey, u.read_from_file(doc_p), u.read_from_file(sign_p))}"
        )
        log.info("End of cverifying files\nTime (in ms): " + (java.lang.System.currentTimeMillis()-st).toString)


      }

      case s: Data_for_verify => {
        u.get_data(s.out_name_file, s.dat)
        top_level_ca ! Get_Certif_Pack(s.cn_user, s.ou_user, s.out_name_file)
      }
    }
  }
}

