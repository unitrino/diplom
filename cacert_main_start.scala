
//import java.rmi.NoSuchObjectException
//import java.util
//import akka.actor._
//
//
//
//import java.util
//import akka.io.Udp.SO.Broadcast
//import cacert.main_cacert.Start_working
//import cacert.main_cacert.Start_working
//import cacert.main_cacert.main_actor
//import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
//import org.bouncycastle.asn1.pkcs.{CertificationRequest, CertificationRequestInfo}
//import org.bouncycastle.asn1._
//import org.bouncycastle.asn1.pkcs.{CertificationRequestInfo, CertificationRequest}
//import org.bouncycastle.asn1.x500.X500Name
//import org.bouncycastle.asn1.x509.Extension
//import org.bouncycastle.asn1.x509.Extension
//import org.bouncycastle.asn1.x509.Extension
//import org.bouncycastle.asn1.x509._
//import org.bouncycastle.cert.jcajce.{JcaX509ContentVerifierProviderBuilder, JcaX509CertificateConverter}
//import org.bouncycastle.cert._
//import org.bouncycastle.cert.ocsp
//import org.bouncycastle.jce.provider.X509CertificateObject
//import org.bouncycastle.operator.{ContentVerifierProvider, ContentSigner}
//import org.bouncycastle.operator.bc.BcDigestCalculatorProvider
//import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
//
//import org.bouncycastle.pkcs.PKCS10CertificationRequest
//import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
//
//import scala.collection.mutable
//import scala.concurrent.duration._
//import scala.concurrent.ExecutionContext.Implicits.global
//
//
////import org.bouncycastle.x509.X509V3CertificateGenerator
////import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure
////import org.bouncycastle.jce.X509Principal
//
//
//import java.io._
//import java.math.BigInteger
//import java.security.InvalidKeyException
//import java.security.KeyPair
//import java.security.KeyPairGenerator
//import java.security.NoSuchProviderException
//import java.security.SecureRandom
//import java.security.Security
//import java.security.SignatureException
//
//import java.security.GeneralSecurityException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.PublicKey;
//import java.security.SignatureException;
//
//import java.util.HashSet;
//import java.util.Set;
//
//
//
//import java.util.Date
//import java.util.Enumeration
//import org.bouncycastle.asn1.x509.KeyUsage
//
//import java.security.{PublicKey, Signature, Principal, PrivateKey}
//
//import javax.security.auth.x500.X500Principal
//import javax.security.cert.CertificateException
//
//import java.security.GeneralSecurityException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.security.NoSuchProviderException;
//import java.security.PublicKey;
//import java.security.SignatureException;
//import java.security.cert.CertPathBuilder;
//import java.security.cert.CertPathBuilderException;
//import java.security.cert.CertStore;
//import java.security.cert.CertificateException;
//import java.security.cert.CollectionCertStoreParameters;
//import java.security.cert.PKIXBuilderParameters;
//import java.security.cert.PKIXCertPathBuilderResult;
//import java.security.cert.TrustAnchor;
//import java.security.cert.X509CertSelector;
//import java.security.cert.X509Certificate;
//import java.security.cert.CertificateFactory
//import java.util.HashSet;
//import java.util.Set;
//
//
//import java.io._
//import java.util.{Hashtable, Properties}
//import javax.naming.{NameNotFoundException, NameAlreadyBoundException, Context}
//import javax.naming.directory._


//trait read_write_files {
//  def read_from_file(path_to:String): Array[Byte] = {
//    val file = new File(path_to)
//    val in = new FileInputStream(file)
//    val file_body = new Array[Byte](file.length().toInt)
//    in.read(file_body)
//    in.close()
//    file_body
//  }
//  def write_to_file(data:Array[Byte],path_to:String) {
//    val file = new File(path_to)
//    val fs = new FileOutputStream(file)
//    fs.write(data)
//    fs.flush()
//  }
//  def copy_files(from:String,to:String): Unit = {
//    //val from_file = new File(from)
//    try {
//      val to_file = new File(to)
//      import java.nio.file._
//      val src = new FileInputStream(from)
//      Files.copy(src, to_file.toPath, StandardCopyOption.REPLACE_EXISTING)
//    }
//    catch {
//      case _:FileNotFoundException => println("File not found.Check path to file.")
//    }
//  }
//}

//trait work_with_signature {
//  def sign_create(priv_key:PrivateKey, file_body_to_sign:Array[Byte],sign: Signature):Signature = {
//    sign.initSign(priv_key)
//    sign.update(file_body_to_sign)
//    sign
//  }
//
//  def verify_sign(key:PublicKey, text_to_ver:Array[Byte], sign_text:Array[Byte]):Boolean = {
//    val sig = Signature.getInstance("SHA1withRSA")
//    sig.initVerify(key)
//    sig.update(text_to_ver)
//    if (sig.verify(sign_text))true
//    else false
//  }
//
//  def verify_certificate(check_certif:X509Certificate, pub_key:PublicKey):Boolean = {
//    val signature = check_certif.getSignature
//    val DER_body = check_certif.getTBSCertificate
//    verify_sign(pub_key,DER_body,signature)
//  }
//}

//trait work_with_certificate {
//  def read_certif_from_file(path_to: String): X509Certificate = {
//    val ff = new File(path_to)
//    val fis = new FileInputStream(ff)
//    val cf = CertificateFactory.getInstance("X.509")
//    val cert = cf.generateCertificate(fis).asInstanceOf[X509Certificate]
//    cert
//  }
//
//  def write_certif_to_file(data: X509Certificate, path_to: String) {
//    val file = new File(path_to+".crt")
//    val fs = new FileOutputStream(file);
//    fs.write(data.getEncoded)
//    fs.flush()
//    println("END WRITING")
//  }
//
//  def generate_RSA_KeyPair(): KeyPair = {
//    val kpGen = KeyPairGenerator.getInstance("RSA")
//    kpGen.initialize(1024, new SecureRandom())
//    return kpGen.generateKeyPair()
//  }
//
//  def generate_request(algorithm: String, dn_path: String, pair: KeyPair): PKCS10CertificationRequest = {
//    val signGen = new JcaContentSignerBuilder(algorithm).build(pair.getPrivate)
//    val subject = new X500Name(dn_path)
//    val builder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic)
//    val csr = builder.build(signGen)
//    csr
//  }
//
//  def generate_v1_certif(serial_numb: BigInteger, dn_path: String,
//                         d_s: Date, d_e: Date, pair: KeyPair, algo: String): X509Certificate = {
//    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
//    val encoded = pair.getPublic.getEncoded
//    val subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded))
//    val out_certif = new X509v3CertificateBuilder(new X500Name(dn_path), serial_numb, d_s, d_e, new X500Name(dn_path), subjectPublicKeyInfo)
//    val signGen = new JcaContentSignerBuilder(algo).build(pair.getPrivate)
//    val cert_holder = out_certif.build(signGen)
//    new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert_holder)
//  }
//
//}

//case class reg_info(request_for_reg:PKCS10CertificationRequest)
//case class out_certif_pack(ca_cert:X509Certificate,user_certif:X509Certificate)
//case class file_with_sing(file_body:Array[Byte],sign:Signature)
//case class req_for_certif_pack(user_dn:String)
//case class file_wrapper(file_data:Array[Byte])
//case class dn_user_path(user_cn:String,user_ou:String)//ZAUZAT


//class user(val usr_cn:String,val usr_ou:String) extends work_with_certificate with read_write_files with work_with_signature {
//  val in_folder: String = "./" + usr_cn + "/in"
//  val out_folder: String = "./" + usr_cn + "/out"
//  val cert_path_ca: String = "./" + usr_cn + "/cacert"
//  val cert_path_users: String = "./" + usr_cn + "/cert_users"
//
//  //GENERATE USER KEY PAIR
//  val key_pair = generate_RSA_KeyPair()
//  val user_private_key = key_pair.getPrivate
//  val user_public_key = key_pair.getPublic
//
//  def start_work() {
//    val in = new File(in_folder)
//    val out = new File(out_folder)
//    val cert_ca = new File(cert_path_ca)
//    val cert_usr = new File(cert_path_users)
//    if (in.mkdirs()) println("Create folder IN for" + usr_cn)
//    if (out.mkdirs()) println("Create folder OUT for" + usr_cn)
//    if (cert_ca.mkdirs()) println("Create folder scala.CA CERT for" + usr_cn)
//    if (cert_usr.mkdirs()) println("Create folder CERT USER for" + usr_cn)
//  }
//
//  def send_req_for_registration(): reg_info = {
//    val dn_path_for_user = "cn=" + usr_cn + ",ou=" + usr_ou
//    return reg_info(generate_request("SHA1withRSA", dn_path_for_user, key_pair))
//  }
//
//  def get_data(name_of_doc: String, f_s: file_with_sing) = {
//    write_to_file(f_s.file_body, in_folder + "/" + name_of_doc)
//    write_to_file(f_s.sign.sign(), in_folder + "/" + name_of_doc + ".sign") // PROVERIT
//  }
//
//  //
//  def get_user_and_ca_certif(pack_doc: out_certif_pack, user_name: String) = {
//    val answ_ca = pack_doc.ca_cert //TEST//
//    val answ_user = pack_doc.user_certif //TEST//
//    write_to_file(answ_ca.getEncoded, cert_path_ca + "/ca_cert.crt")
//    write_to_file(answ_user.getEncoded, cert_path_users + "/" + user_name + ".crt") // PROVERIT
//  }
//
//  def get_ca_and_user_paths(user_name: String): (String, String) = (cert_path_ca + "/ca_cert.crt", cert_path_users + "/" + user_name + ".crt")
//
//  def get_doc_and_sign_paths(name_of_doc: String): (String, String) = (in_folder + "/" + name_of_doc, in_folder + "/" + name_of_doc + ".sign")
//
//
//  def sign_document(path_to_doc: String): Signature = {
//    val ins = Signature.getInstance("SHA1withRSA") //TEST//
//    val sig = sign_create(user_private_key, read_from_file(path_to_doc), ins)
//    sig
//  }
//
//  def verify_sing_to_file(path_to_sig_file: String, path_to_file: String, algo: String): Boolean = {
//    val rez = verify_sign(user_public_key, read_from_file(path_to_file), read_from_file(path_to_sig_file))
//    rez
//  }
//}

//class CA(ca_name: String, level: String,ldap_login:String,ldap_pass:String) extends work_with_certificate with read_write_files {
//
//  val key_pair = generate_RSA_KeyPair()
//  val ca_private_key = key_pair.getPrivate()
//  val ca_public_key = key_pair.getPublic()
//  val ca_dn_path = "cn=" + ca_name + ",ou=" + level
//  val algo = "SHA1withRSA"
//  var ca_cert: X509Certificate = null
//  val ldap = new LDAP_db(ldap_login,ldap_pass)
//  //var request:PKCS10CertificationRequest = null //CHECK!!!!!!!!!!!!!!!!!!
//
//
//  def get_cert_pack(user_cn_path: String, user_ou_path: String): (X509Certificate, X509Certificate) = {
//    val out_path = "cn=" + user_cn_path + ",ou=" + user_ou_path
//    val bytes_cert = ldap.extract_data(out_path).file_data
//    val cf = CertificateFactory.getInstance("X.509","BC")
//    val byte_stream = new ByteArrayInputStream(bytes_cert)
//    val cert = cf.generateCertificate(byte_stream).asInstanceOf[X509Certificate]
//    (cert, ca_cert)
//  }
//
//  def create_self_certif() {
//    ca_cert = generate_v1_certif(BigInteger.valueOf(System.currentTimeMillis()),
//      ca_dn_path, new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + 100000000), key_pair, algo)
//    ldap.add_with_check(ca_dn_path, file_wrapper(ca_cert.getEncoded))
//  }
//
//  def ret_certif = ca_cert
//
//  def create_certif_for_user(req_data: reg_info) = {
//    //    println("Checking request consintancy")
//    val zz = new JcaX509ContentVerifierProviderBuilder().build(req_data.request_for_reg.getSubjectPublicKeyInfo)
//    //    println(req_data.request_for_reg.isSignatureValid(zz))
//    println(s"CHECK REQUEST CONSIST ${req_data.request_for_reg.getSubject} is - " +
//      s"${req_data.request_for_reg.isSignatureValid(zz)}")
//
//    val serial_numb = BigInteger.valueOf(System.currentTimeMillis())
//    val data_start = new Date(System.currentTimeMillis())
//    val data_end = new Date(System.currentTimeMillis() + 100000000)
//
//    val out_sing_cert = generate_v3_certif(algo, ca_cert, req_data.request_for_reg, serial_numb, data_start, data_end, false)
//    ldap.add_with_check(req_data.request_for_reg.getSubject.toString, file_wrapper(out_sing_cert.getEncoded))
//    out_sing_cert
//  }
//
//  def create_certif_for_ca(f: Boolean, req_data: reg_info): X509Certificate = {
//    val zz = new JcaX509ContentVerifierProviderBuilder().build(req_data.request_for_reg.getSubjectPublicKeyInfo)
//    //println(req_data.request_for_reg.isSignatureValid(zz))
//    println(s"CHECK REQUEST CONSIST ${req_data.request_for_reg.getSubject} is - " +
//      s"${req_data.request_for_reg.isSignatureValid(zz)}")
//    val serial_numb = BigInteger.valueOf(System.currentTimeMillis())
//    val data_start = new Date(System.currentTimeMillis())
//    val data_end = new Date(System.currentTimeMillis() + 100000000)
//
//    val out_sing_cert = generate_v3_certif(algo, ca_cert, req_data.request_for_reg, serial_numb, data_start, data_end, f)
//    ldap.add_with_check(req_data.request_for_reg.getSubject.toString, file_wrapper(out_sing_cert.getEncoded))
//    out_sing_cert
//  }
//
//  def generate_v3_certif(algo: String, higher_certif: X509Certificate, request: PKCS10CertificationRequest,
//                         serial_numb: BigInteger, d_s: Date, d_e: Date, flag_ca: Boolean): X509Certificate = {
//
//    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
//
//    val subjectPublicKeyInfo: SubjectPublicKeyInfo = request.getSubjectPublicKeyInfo
//
//    val out_certif = new X509v3CertificateBuilder(new X500Name(higher_certif.getSubjectDN.toString),
//      serial_numb, d_s, d_e,
//      request.getSubject,
//      subjectPublicKeyInfo)
//
//    val digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1))
//    val x509ExtensionUtils = new X509ExtensionUtils(digCalc)
//    out_certif.addExtension(Extension.authorityKeyIdentifier, true, x509ExtensionUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo))
//    if (flag_ca) {
//      val ku = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature)
//      out_certif.addExtension(Extension.keyUsage, false, ku)
//      out_certif.addExtension(Extension.basicConstraints, false, new BasicConstraints(true))
//      out_certif.addExtension(Extension.subjectKeyIdentifier, true, x509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo))
//    }
//    else {
//      out_certif.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
//      out_certif.addExtension(Extension.subjectKeyIdentifier, true, x509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo))
//    }
//    val signGen = new JcaContentSignerBuilder(algo).build(ca_private_key)
//    val cert_holder = out_certif.build(signGen)
//    new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert_holder)
//  }
//
//  def generate_req: PKCS10CertificationRequest = {
//    val req = generate_request(algo, ca_dn_path, key_pair)
//    req
//  }
//}

//case object Create_Req_CA
//
//case object Create_CA
//
//case object Req_For_Certif
//
//case class Answ_Req_For_Certif(answ: X509Certificate)
//
//case class Send_Req_For_Reg(flag: Boolean, req: reg_info, owner: ActorRef)
//
//case class Send_Req_For_User_Reg(req: reg_info, owner: ActorRef,data:Sending_Data)
//
//case object Create_Cert_For_User
//
//case class Create_Top_Cert_For_User(cert: X509Certificate,data:Sending_Data)
//
//case class Create_Top_Cert(cert: X509Certificate)
//
//case class Get_Certif_Pack(cn_u: String, ou_u: String, path_to_files: String)
//
//case class Answer_Certificates(user_cert: X509Certificate, ca_cert: X509Certificate, cn_u: String, ou_u: String, path_to_files: String)
//
//class CA_Actor(top_level_ca: ActorRef, ca_obj: CA) extends Actor {
//  def receive = {
//    case Create_CA if top_level_ca == null => {
//      ca_obj.create_self_certif()
//      val ca_top_certif = ca_obj.ret_certif
//      ca_obj.write_to_file(ca_top_certif.getEncoded, ca_obj.ca_dn_path + ".crt")
//    }
//    case Req_For_Certif => sender ! Answ_Req_For_Certif(ca_obj.ca_cert)
//    case Create_Req_CA => {
//      val reqq = reg_info(ca_obj.generate_req)
//      top_level_ca ! Send_Req_For_Reg(true, reqq, self)
//    }
//    case s: Send_Req_For_Reg => {
//      if (ca_obj.ca_cert != null) {
//        s.owner ! Create_Top_Cert(ca_obj.create_certif_for_ca(s.flag, s.req))
//      }
//      else {
//        self ! s
//      }
//    }
//    case s: Send_Req_For_User_Reg =>
//      if (ca_obj.ca_cert != null) {
//        val cert_out:X509Certificate = if (ca_obj.ldap.is_elem_in_ldap(s.req.request_for_reg.getSubject.toString)) {
//          println(s"VALUE EXISTS ${s.req.request_for_reg.getSubject.toString}")
//          val arg = s.req.request_for_reg.getSubject.toString.split(',')
//          val c1 = ca_obj.get_cert_pack(arg(0).substring(3),arg(1).substring(3))._1
//          c1
//        }
//        else
//        {
//          println(s"VALUE IS NOT EXISTS ${s.req.request_for_reg.getSubject.toString}")
//          ca_obj.create_certif_for_user(s.req)
//        }
//        s.owner ! Create_Top_Cert_For_User(cert_out,s.data)
//      }
//      else {
//        self ! s
//      }
//    case s: Create_Top_Cert => {
//      ca_obj.ca_cert = s.cert
//      ca_obj.write_to_file(ca_obj.ca_cert.getEncoded, ca_obj.ca_dn_path + ".crt")
//    }
//    case s: Get_Certif_Pack => {
//      val (user, ca) = ca_obj.get_cert_pack(s.cn_u, s.ou_u)
//      sender ! Answer_Certificates(user, ca, s.cn_u, s.ou_u, s.path_to_files)
//    }
//  }
//}
//case class Sending_Data(send_to: ActorRef, path_to_file: String, out_name_file: String)
//
//case class Create_Req_User(data:Sending_Data)
//
//case class Create_Sing(data:Sending_Data)
//
////Create_Sing(doc_path:String)
//case class Verify_Certificate(cn_user: String, ou_user: String)
//
//case class Data_for_verify(cn_user: String, ou_user: String, dat: file_with_sing, path_to_file_send: String, out_name_file: String)
//
//class User_Actor(top_level_ca: ActorRef, u: user) extends Actor with read_write_files{
//
//  //val data_for_sending = new ListBuffer[(ActorRef, String, String)]()
//
//  override def preStart = u.start_work()
//
//  def receive = {
//    case s: Create_Req_User => {
//      copy_files(s.data.path_to_file,u.out_folder + "/" + new File(s.data.path_to_file).getName)
//      val reqq = u.send_req_for_registration()
//      top_level_ca ! Send_Req_For_User_Reg(reqq, self,s.data)
//    }
//    case s:Create_Top_Cert_For_User => {
//      write_to_file(s.cert.getEncoded,u.cert_path_users + "/" + u.usr_cn + ".crt")
//      println(s"REGISTRATION COMPLETE for ${s.cert.getSubjectDN}")
//      self ! Create_Sing(s.data)
//    }
//    case s:Create_Sing => {
//      try {
//        val signat = u.sign_document(s.data.path_to_file)
//        val dat = file_with_sing(u.read_from_file(s.data.path_to_file), signat)
//        s.data.send_to ! Data_for_verify(u.usr_cn, u.usr_ou, dat, s.data.path_to_file, s.data.out_name_file)
//      }
//      catch {
//        case _:FileNotFoundException => println(s"Incorrect file path to send ${s.data.path_to_file}")
//      }
//    }
//    //send_to_user ! Data_for_verify(u.usr_cn,u.usr_ou,dat)
//    //    case s:Verify_Certificate => {
//    //      top_level_ca ! Get_Certif_Pack(s.cn_user,s.ou_user)
//    //    }
//    case s: Answer_Certificates => {
//      write_to_file(s.ca_cert.getEncoded,u.cert_path_ca + "/ca_cert.crt")
//      write_to_file(s.user_cert.getEncoded,u.cert_path_users + "/" + s.cn_u + ".crt")
//      println(s"Verify certificate to ${u.usr_cn}" +
//        s" from ${s.cn_u} is ${u.verify_certificate(s.user_cert, s.ca_cert.getPublicKey)}"
//      )
//      //println(u.verify_certificate(s.user_cert, s.ca_cert.getPublicKey))
//      val (doc_p, sign_p) = u.get_doc_and_sign_paths(s.path_to_files)
//      //println("Verify document "+ u.usr_cn)
//      //println(u.verify_sign(s.user_cert.getPublicKey, u.read_from_file(doc_p), u.read_from_file(sign_p)))
//
//      println(s"Verify document ${doc_p} to ${u.usr_cn}" +
//        s" from ${s.cn_u} is ${u.verify_sign(s.user_cert.getPublicKey, u.read_from_file(doc_p), u.read_from_file(sign_p))}"
//      )
//
//
//    }
//
//    case s: Data_for_verify => {
//      u.get_data(s.out_name_file, s.dat)
//      //self ! Verify_Certificate(s.cn_user,s.ou_user)
//      top_level_ca ! Get_Certif_Pack(s.cn_user, s.ou_user, s.out_name_file)
//    }
//  }
//}
//case object Start_working

//class main_actor(path_xml:String,ldap_login:String,ldap_pass:String) extends Actor {
//  import scala.concurrent.duration._
//
//  def receive = {
//    case Start_working =>
//    {
//      context.setReceiveTimeout(10 seconds)
//      val xml = new XML_Checker_And_Parser(path_xml)
//      val data = xml.load_xml_check
//      val map_actors_ca = mutable.Map[String,ActorRef]()
//      val map_actors_user = mutable.Map[String,(ActorRef,List[(String,String,String,String)])]()
//      if (xml.check_user_fields(data)) {
//        if (xml.check_ca_fields(data)) {
//          xml.parse_ca_result(data) foreach {
//            data_ca =>
//              val (ca_org, ca_name, top_ca) = data_ca
//              if (top_ca == "null") {
//                val CA_top = new CA(ca_name, ca_org,ldap_login,ldap_pass)
//                val top = context.actorOf(Props(new CA_Actor(null, CA_top)), ca_name + "_actor")
//                top ! Create_CA
//                map_actors_ca += ((ca_name + "_actor",top))
//              }
//              else {
//                val CA_middle = new CA(ca_name, ca_org,ldap_login,ldap_pass)
//                val top_actor = map_actors_ca.get(top_ca+"_actor").get
//                val middle = context.actorOf(Props(new CA_Actor(top_actor, CA_middle)), ca_name + "_actor")
//                middle ! Create_Req_CA
//                map_actors_ca += ((ca_name + "_actor",middle))
//              }
//          }
//
//          xml.parse_user_result(data) foreach { batch_data =>
//            val (top_ca_name,org_name, user_name, send_to) = batch_data
//            val new_user_obj = new user(user_name, org_name)
//            val top_actor = map_actors_ca.get(top_ca_name+"_actor").get
//            val user_actor = context.actorOf(Props(new User_Actor(top_actor, new_user_obj)), user_name + "_user_actor")
//            map_actors_user += ((user_name + "_" +org_name,(user_actor,send_to.toList)))
//          }
//          map_actors_user foreach {
//            massive_actors => {
//                val (user_full_name,(user_actor,user_data)) = massive_actors
//                if (user_data.size != 0) {
//                      val (send_to_user, _) = map_actors_user.get(user_data(0)._2 + "_" + user_data(0)._1).get
//                      val file_path = user_data(0)._3
//                      val new_file_path = user_data(0)._4
//                      user_actor ! Create_Req_User(Sending_Data(send_to_user, file_path, new_file_path))
//                }
//            }
//          }
//        }
//        else println("ERROR CA XML")
//      }
//      else println("ERROR USER XML")
//
//
////      val CA_top = new CA("ca_top_1", "top")
////      val top = context.actorOf(Props(new CA_Actor(null, CA_top)), "ca_top")
////      top ! Create_CA
////
////      val CA_middle = new CA("ca_2", "middle")
////      val middle = context.actorOf(Props(new CA_Actor(top, CA_middle)), "ca_middle")
////      middle ! Create_Req_CA
////
////      val CA_bottom = new CA("ca_3", "bottom")
////      val bottom = context.actorOf(Props(new CA_Actor(middle, CA_bottom)), "ca_bottom")
////      bottom ! Create_Req_CA
////
////      val u2 = new user("Sveta", "Intel")
////      val user2 = context.actorOf(Props(new User_Actor(bottom, u2)), "user_2")
////
////      val u1 = new user("Dasha", "Intel")
////      val user1 = context.actorOf(Props(new User_Actor(bottom, u1)), "user_1")
////
////      val u3 = new user("Ford", "Intel")
////      val user3 = context.actorOf(Props(new User_Actor(bottom, u3)), "user_3")
////
////      user1 ! Create_Req_User(Sending_Data(user2, "./1.doc", "out_doc333.doc"))
////      user1 ! Create_Req_User(Sending_Data(user2, "./1.pdf", "out_dfc333.pdf"))
////      user3 ! Create_Req_User(Sending_Data(user1, "./1.pdf", "out_ford333.pdf"))
////      user3 ! Create_Req_User(Sending_Data(user2, "./1.doc", "out_ford.doc"))
//
//    }
//    case ReceiveTimeout => {
//      println("Clearing LDAP")
//      val clear_ldap = new LDAP_db(ldap_login,ldap_pass)
//      clear_ldap.clear_ldap
//      context.system.shutdown()
//    }
//  }
//}

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

//class LDAP_db(user:String,password:String) extends read_write_files {
//  val domm = "cacertdomain"
//  val url = "ldap://localhost:389" + "/dc=" + domm
//  var env = new Hashtable[String, String]()
//
//  env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
//  env.put(Context.PROVIDER_URL, url)
//  env.put(Context.SECURITY_AUTHENTICATION, "simple")
//  env.put(Context.SECURITY_PRINCIPAL, "cn=" + user + ",dc=" + domm)
//  env.put(Context.SECURITY_CREDENTIALS, password)
//
//  val dir_context = new InitialDirContext(env)
//
//
//  def add_ou(dn_path: String) = {
//    val cn_name = dn_path.split(',')(0)
//    val ou_name = dn_path.split(',')(1)
//    val attrs = new BasicAttributes(true)
//    val objclass = new BasicAttribute("objectclass")
//    objclass.add("organizationalUnit")
//    attrs.put(objclass)
//    try {
//      dir_context.bind(ou_name, null, attrs)
//    }
//    catch {
//      case _ => println("OU EXISTS")
//    }
//  }
//
//  def change_attributes(dn_path: String, file_data: file_wrapper) = {
//    val my_attrib = new BasicAttributes(true)
//    val oc = new BasicAttribute("javaSerializedData")
//    val b = new ByteArrayOutputStream()
//    val o = new ObjectOutputStream(b)
//    o.writeObject(file_data)
//    val znach = b.toByteArray()
//    oc.add(znach)
//    my_attrib.put(oc)
//    dir_context.modifyAttributes(dn_path, DirContext.REPLACE_ATTRIBUTE, my_attrib)
//  }
//
//  def delete_elem(dn_path: String) = dir_context.destroySubcontext(dn_path)
//
//  def clear_ldap = {
//    import collection.JavaConverters._
//    val nameIterator = dir_context.listBindings("").asScala
//    nameIterator.foreach {
//      case ou => val j = dir_context.listBindings(ou.getName).asScala.foreach { case cn =>
//        delete_elem(cn.getName + "," + ou.getName)
//      }
//    }
//
//  }
//  def rename_attrib(new_path: String, old_path: String) = dir_context.rename(old_path, new_path)
//
//  def is_elem_in_ldap(dn_path: String) : Boolean = {
//    try {
//      dir_context.lookup(dn_path)
//      true
//    }
//    catch {
//      case _:NameNotFoundException => false
//    }
//
//  }
//  def extract_data(dn_path: String): file_wrapper = {
//    try {
//      dir_context.lookup(dn_path).asInstanceOf[file_wrapper]
//    }
//    catch {
//      case _:NameNotFoundException => println("Object not in LDAP"); null
//    }
//  }
//
//  def add_with_check(dn_path: String, file_data: file_wrapper) = {
//    try {
//      println(s"ADD TO LDAP ${dn_path}")
//      add_ou(dn_path)
//      dir_context.bind(dn_path, file_data)
//    }
//    catch {
//      case _: NameAlreadyBoundException => change_attributes(dn_path, file_data)
//    }
//  }
//
//  def close_connect = dir_context.close()
//}

//class XML_Checker_And_Parser(path_to_xml:String) {
//  import scala.xml._
//  def load_xml_check: Node = {
//    try {
//      val ff = scala.xml.XML.loadFile(path_to_xml)
//      ff
//    }
//    catch {
//      case _: SAXParseException => println("Incorrect XML file")
//        null
//    }
//  }
//
//  def check_ca_fields(file_body:Node):Boolean = {
//    (file_body \ "new_ca") forall {
//      x1: Node => {
//        if ((x1 \ "ca_organization").text == "") {
//          println(s"ERROR in section 'new_ca', ERROR  'ca_organization' :\n${x1.toString()}")
//          false
//        }
//        else if ((x1 \ "ca_name").text == "") {
//          println(s"ERROR in section 'new_ca', ERROR  'ca_name' :\n${x1.toString()}")
//          false
//        }
//        else if ((x1 \ "top_ca").text == "") {
//          println(s"ERROR in section 'new_ca', ERROR  'top_ca' :\n${x1.toString()}")
//          false
//        }
//        else true
//      }
//    }
//  }
//
//  def check_user_fields(file_body:Node):Boolean = {
//    (file_body \ "new_user").forall{
//      x1:Node => {
//        if ((x1 \ "user_organization").text == "") {
//          println(s"ERROR in first section 'user_organization' :\n${x1.toString()}")
//          false
//        }
//        else if ((x1 \ "user_name").text == "") {
//          println(s"ERROR in first section 'user_name' :\n${x1.toString()}")
//          false
//        }
//        else if ((x1 \ "top_ca").text == "") {
//          println(s"ERROR in first section 'top_ca' :\n${x1.toString()}")
//          false
//        }
//        else if ((file_body \ "new_user" \ "send_to").text != "") {
//            (file_body \ "new_user" \ "send_to") forall {
//            x2: Node => {
//              if ((x2 \ "user_organization").text == "") {
//                println(s"ERROR in 'SEND TO' section, ERROR  'user_organization' :\n${x2.toString()}")
//                false
//              }
//              else if ((x2 \ "user_name").text == "") {
//                println(s"ERROR in 'SEND TO' section, ERROR  'user_name' :\n${x2.toString()}")
//                false
//              }
//              else if ((x2 \ "file_to_send").text == "") {
//                println(s"ERROR in  'SEND TO' section, ERROR  'file_to_send' :\n${x2.toString()}")
//                false
//              }
//              else if ((x2 \ "outputfile_name").text == "") {
//                println(s"ERROR in  'SEND TO' section, ERROR  'outputfile_name' :\n${x2.toString()}")
//                false
//              }
//              else true
//            }
//          }
//        }
//        else true
//      }
//    }
//  }
//
//  def parse_user_result(file_body:Node)= {
//    (file_body \ "new_user").map { x => {
//      ((x \ "top_ca").text,(x \ "user_organization").text, (x \ "user_name").text,
//        (x \ "send_to").map(y => ((y \ "user_organization").text, (y \ "user_name").text, (y \ "file_to_send").text, (y \ "outputfile_name").text)))
//    }
//    }
//  }
//
//
//  def parse_ca_result(file_body:Node) = {
//      (file_body \ "new_ca").map { x => {
//        ((x \ "ca_organization").text, (x \ "ca_name").text,(x \ "top_ca").text)
//      }
//    }
//  }
//}


