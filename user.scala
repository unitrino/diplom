package cacert.user {

import java.io.File
import java.security.Signature

import cacert.messages_for_certificate.{file_with_sing, reg_info, out_certif_pack}
import cacert.read_write_files.read_write_files
import cacert.work_with_certificate.work_with_certificate
import cacert.work_with_signature.work_with_signature

class user(val usr_cn:String,val usr_ou:String) extends work_with_certificate with read_write_files with work_with_signature {
  private val in_folder: String = "./" + usr_cn + "/in"
  private val out_folder: String = "./" + usr_cn + "/out"
  private val cert_path_ca: String = "./" + usr_cn + "/cacert"
  private val cert_path_users: String = "./" + usr_cn + "/cert_users"

  //GENERATE USER KEY PAIR
  private val key_pair = generate_RSA_KeyPair()
  private val user_private_key = key_pair.getPrivate
  private val user_public_key = key_pair.getPublic

  def ret_folder_path = (in_folder,out_folder,cert_path_ca,cert_path_users)

  def start_work() {
    val in = new File(in_folder)
    val out = new File(out_folder)
    val cert_ca = new File(cert_path_ca)
    val cert_usr = new File(cert_path_users)
    if (in.mkdirs()) println("Create folder IN for" + usr_cn)
    if (out.mkdirs()) println("Create folder OUT for" + usr_cn)
    if (cert_ca.mkdirs()) println("Create folder scala.CA CERT for" + usr_cn)
    if (cert_usr.mkdirs()) println("Create folder CERT USER for" + usr_cn)
  }

  def send_req_for_registration(): reg_info = {
    val dn_path_for_user = "cn=" + usr_cn + ",ou=" + usr_ou
    return reg_info(generate_request("SHA1withRSA", dn_path_for_user, key_pair))
  }

  def get_data(name_of_doc: String, f_s: file_with_sing) = {
    write_to_file(f_s.file_body, in_folder + "/" + name_of_doc)
    write_to_file(f_s.sign.sign(), in_folder + "/" + name_of_doc + ".sign") // PROVERIT
  }

  //
  def get_user_and_ca_certif(pack_doc: out_certif_pack, user_name: String) = {
    val answ_ca = pack_doc.ca_cert //TEST//
    val answ_user = pack_doc.user_certif //TEST//
    write_to_file(answ_ca.getEncoded, cert_path_ca + "/ca_cert.crt")
    write_to_file(answ_user.getEncoded, cert_path_users + "/" + user_name + ".crt") // PROVERIT
  }

  def get_ca_and_user_paths(user_name: String): (String, String) = (cert_path_ca + "/ca_cert.crt", cert_path_users + "/" + user_name + ".crt")

  def get_doc_and_sign_paths(name_of_doc: String): (String, String) = (in_folder + "/" + name_of_doc, in_folder + "/" + name_of_doc + ".sign")


  def sign_document(path_to_doc: String): Signature = {
    val ins = Signature.getInstance("SHA1withRSA") //TEST//
    val sig = sign_create(user_private_key, read_from_file(path_to_doc), ins)
    sig
  }

  def verify_sing_to_file(path_to_sig_file: String, path_to_file: String, algo: String): Boolean = {
    val rez = verify_sign(user_public_key, read_from_file(path_to_file), read_from_file(path_to_sig_file))
    rez
  }
}
}
