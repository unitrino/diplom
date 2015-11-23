
import akka.actor.{Props, ActorSystem}
import cacert.main_cacert.Start_working
import cacert.main_cacert.main_actor

object cacert_main_start extends App {

  if (this.args.length != 3) {
    println("Incorrect number of args")
  }
  else {
    if (!this.args(2).endsWith(".xml")) println("Last argument must be XML file")
    else {
      val ss = ActorSystem("system")
      val Main_actor = ss.actorOf(Props(new main_actor(this.args(2), this.args(0), this.args(1))), "main_akka")
      Main_actor ! Start_working
      ss.awaitTermination()
    }
  }

}