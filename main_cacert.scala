package cacert.main_cacert {

import akka.actor.{Props, ReceiveTimeout, ActorRef, Actor}
import akka.event.Logging
import cacert.CA.CA
import cacert.certificate_actor.{Create_Req_CA, Create_CA, CA_Actor}
import cacert.ldap_db.LDAP_db
import cacert.user.user
import cacert.user_actor.{Sending_Data, Create_Req_User, User_Actor}
import cacert.xml_checker_and_parser.XML_Checker_And_Parser
import org.joda.time.{Seconds, DateTime}
import scala.collection.mutable


class main_actor(path_xml:String,ldap_login:String,ldap_pass:String) extends Actor {
  import scala.concurrent.duration._
  private val log = Logging(context.system.eventStream, self.path.name)
  def receive = {
    case Start_working =>
    {
      val st1 = java.lang.System.currentTimeMillis()
      context.setReceiveTimeout(3 seconds)
      log.info("Start working Main actor")
      val xml = new XML_Checker_And_Parser(path_xml)
      val data = xml.load_xml_check
      val map_actors_ca = mutable.Map[String,ActorRef]()
      val map_actors_user = mutable.Map[String,(ActorRef,List[(String,String,String,String)])]()
      if (xml.check_user_fields(data)) {
        if (xml.check_ca_fields(data)) {
          xml.parse_ca_result(data) foreach {
            data_ca =>
              val (ca_org, ca_name, top_ca) = data_ca
              if (top_ca == "null") {
                log.info("Root CA cert create")
                val CA_top = new CA(ca_name, ca_org,ldap_login,ldap_pass)
                val top = context.actorOf(Props(new CA_Actor(null, CA_top)), ca_name + "_actor")
                top ! Create_CA
                map_actors_ca += ((ca_name + "_actor",top))
              }
              else {
                log.info("Sub CA cert create")
                val CA_middle = new CA(ca_name, ca_org,ldap_login,ldap_pass)
                val top_actor = map_actors_ca.get(top_ca+"_actor").get
                val middle = context.actorOf(Props(new CA_Actor(top_actor, CA_middle)), ca_name + "_actor")
                middle ! Create_Req_CA
                map_actors_ca += ((ca_name + "_actor",middle))
              }
          }
          log.info("CA cert create ENDIND\nTime (in ms): " + (java.lang.System.currentTimeMillis()-st1).toString)
          val st3 = java.lang.System.currentTimeMillis()
          xml.parse_user_result(data) foreach { batch_data =>
            val (top_ca_name,org_name, user_name, send_to) = batch_data
            val new_user_obj = new user(user_name, org_name)
            val top_actor = map_actors_ca.get(top_ca_name+"_actor").get
            val user_actor = context.actorOf(Props(new User_Actor(top_actor, new_user_obj)), user_name + "_user_actor")
            map_actors_user += ((user_name + "_" +org_name,(user_actor,send_to.toList)))
          }
          log.info("Users create end\nTime (in ms): " + (java.lang.System.currentTimeMillis()-st3).toString)
          //log.info("Time (in ms): " + (java.lang.System.currentTimeMillis()-st3).toString)
          val st4 = java.lang.System.currentTimeMillis()
          map_actors_user foreach {
            massive_actors => {
              val (user_full_name,(user_actor,user_data)) = massive_actors
              if (user_data.size != 0) {
                val (send_to_user, _) = map_actors_user.get(user_data(0)._2 + "_" + user_data(0)._1).get
                val file_path = user_data(0)._3
                val new_file_path = user_data(0)._4
                user_actor ! Create_Req_User(Sending_Data(send_to_user, file_path, new_file_path))
              }
            }
          }
          log.info("All message are being sent\nTime (in ms): " + (java.lang.System.currentTimeMillis()-st4).toString)
        }
        else println("ERROR CA XML")
      }
      else println("ERROR USER XML")
    }
    case ReceiveTimeout => {
      log.info("Clearing LDAP")
      val clear_ldap = new LDAP_db(ldap_login,ldap_pass)
      clear_ldap.clear_ldap
      clear_ldap.close_connect
      context.system.shutdown()
    }
  }
}
case object Start_working
}
