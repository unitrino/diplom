package cacert.xml_checker_and_parser {

import scala.xml._

class XML_Checker_And_Parser(path_to_xml:String) {
  def load_xml_check: Node = {
    try {
      val ff = scala.xml.XML.loadFile(path_to_xml)
      ff
    }
    catch {
      case _: SAXParseException => println("Incorrect XML file")
        null
    }
  }

  def check_ca_fields(file_body:Node):Boolean = {
    (file_body \ "new_ca") forall {
      x1: Node => {
        if ((x1 \ "ca_organization").text == "") {
          println(s"ERROR in section 'new_ca', ERROR  'ca_organization' :\n${x1.toString()}")
          false
        }
        else if ((x1 \ "ca_name").text == "") {
          println(s"ERROR in section 'new_ca', ERROR  'ca_name' :\n${x1.toString()}")
          false
        }
        else if ((x1 \ "top_ca").text == "") {
          println(s"ERROR in section 'new_ca', ERROR  'top_ca' :\n${x1.toString()}")
          false
        }
        else true
      }
    }
  }

  def check_user_fields(file_body:Node):Boolean = {
    (file_body \ "new_user").forall{
      x1:Node => {
        if ((x1 \ "user_organization").text == "") {
          println(s"ERROR in first section 'user_organization' :\n${x1.toString()}")
          false
        }
        else if ((x1 \ "user_name").text == "") {
          println(s"ERROR in first section 'user_name' :\n${x1.toString()}")
          false
        }
        else if ((x1 \ "top_ca").text == "") {
          println(s"ERROR in first section 'top_ca' :\n${x1.toString()}")
          false
        }
        else if ((file_body \ "new_user" \ "send_to").text != "") {
          (file_body \ "new_user" \ "send_to") forall {
            x2: Node => {
              if ((x2 \ "user_organization").text == "") {
                println(s"ERROR in 'SEND TO' section, ERROR  'user_organization' :\n${x2.toString()}")
                false
              }
              else if ((x2 \ "user_name").text == "") {
                println(s"ERROR in 'SEND TO' section, ERROR  'user_name' :\n${x2.toString()}")
                false
              }
              else if ((x2 \ "file_to_send").text == "") {
                println(s"ERROR in  'SEND TO' section, ERROR  'file_to_send' :\n${x2.toString()}")
                false
              }
              else if ((x2 \ "outputfile_name").text == "") {
                println(s"ERROR in  'SEND TO' section, ERROR  'outputfile_name' :\n${x2.toString()}")
                false
              }
              else true
            }
          }
        }
        else true
      }
    }
  }

  def parse_user_result(file_body:Node)= {
    (file_body \ "new_user").map { x => {
      ((x \ "top_ca").text,(x \ "user_organization").text, (x \ "user_name").text,
        (x \ "send_to").map(y => ((y \ "user_organization").text, (y \ "user_name").text, (y \ "file_to_send").text, (y \ "outputfile_name").text)))
    }
    }
  }


  def parse_ca_result(file_body:Node) = {
    (file_body \ "new_ca").map { x => {
      ((x \ "ca_organization").text, (x \ "ca_name").text,(x \ "top_ca").text)
    }
    }
  }
}
}
