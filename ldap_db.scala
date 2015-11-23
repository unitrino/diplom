package cacert.ldap_db {

import java.io.{ObjectOutputStream, ByteArrayOutputStream}
import java.util.Hashtable
import javax.naming.{NameAlreadyBoundException, NameNotFoundException, Context}
import javax.naming.directory.{DirContext, BasicAttribute, BasicAttributes, InitialDirContext}

import cacert.messages_for_certificate.file_wrapper
import cacert.read_write_files.read_write_files
import org.slf4j.LoggerFactory

class LDAP_db(user: String, password: String) extends read_write_files {
  import com.typesafe.scalalogging._
  private val logger = Logger(LoggerFactory.getLogger(this.getClass))
  private val domm = "cacertdomain"
  private val url = "ldap://localhost:389" + "/dc=" + domm
  private val env = new Hashtable[String, String]()

  env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
  env.put(Context.PROVIDER_URL, url)
  env.put(Context.SECURITY_AUTHENTICATION, "simple")
  env.put(Context.SECURITY_PRINCIPAL, "cn=" + user + ",dc=" + domm)
  env.put(Context.SECURITY_CREDENTIALS, password)

  private val dir_context = new InitialDirContext(env)


  def add_ou(dn_path: String) = {
    val cn_name = dn_path.split(',')(0)
    val ou_name = dn_path.split(',')(1)
    val attrs = new BasicAttributes(true)
    val objclass = new BasicAttribute("objectclass")
    objclass.add("organizationalUnit")
    attrs.put(objclass)
    try {
      dir_context.bind(ou_name, null, attrs)
    }
    catch {
      case _:NameNotFoundException => logger.info("OU EXISTS")
    }
  }

  def change_attributes(dn_path: String, file_data: file_wrapper) = {
    val my_attrib = new BasicAttributes(true)
    val oc = new BasicAttribute("javaSerializedData")
    val b = new ByteArrayOutputStream()
    val o = new ObjectOutputStream(b)
    o.writeObject(file_data)
    val znach = b.toByteArray()
    oc.add(znach)
    my_attrib.put(oc)
    dir_context.modifyAttributes(dn_path, DirContext.REPLACE_ATTRIBUTE, my_attrib)
  }

  def delete_elem(dn_path: String) = dir_context.destroySubcontext(dn_path)

  def clear_ldap = {
    import collection.JavaConverters._
    val nameIterator = dir_context.listBindings("").asScala
    nameIterator.foreach {
      case ou => {
                dir_context.listBindings(ou.getName).asScala.foreach { case cn =>
                delete_elem(cn.getName + "," + ou.getName) }
                delete_elem(ou.getName)
                }
      }
  }

  def rename_attrib(new_path: String, old_path: String) = dir_context.rename(old_path, new_path)

  def is_elem_in_ldap(dn_path: String): Boolean = {
    try {
      dir_context.lookup(dn_path)
      true
    }
    catch {
      case _: NameNotFoundException => false
    }

  }

  def extract_data(dn_path: String): file_wrapper = {
    try {
      dir_context.lookup(dn_path).asInstanceOf[file_wrapper]
    }
    catch {
      case _: NameNotFoundException => println("Object not in LDAP"); null
    }
  }

  def add_with_check(dn_path: String, file_data: file_wrapper) = {
    try {
      logger.info(s"ADD TO LDAP ${dn_path}")
      add_ou(dn_path)
      dir_context.bind(dn_path, file_data)
    }
    catch {
      case _: NameAlreadyBoundException => change_attributes(dn_path, file_data)
    }
  }

  def close_connect = dir_context.close()
}

}
