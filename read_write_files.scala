
package cacert.read_write_files {

import java.io.{FileNotFoundException, FileOutputStream, FileInputStream, File}

trait read_write_files {
  def read_from_file(path_to: String): Array[Byte] = {
    val file = new File(path_to)
    val in = new FileInputStream(file)
    val file_body = new Array[Byte](file.length().toInt)
    in.read(file_body)
    in.close()
    file_body
  }

  def write_to_file(data: Array[Byte], path_to: String) {
    val file = new File(path_to)
    val fs = new FileOutputStream(file)
    fs.write(data)
    fs.flush()
  }

  def copy_files(from: String, to: String): Unit = {
    //val from_file = new File(from)
    try {
      val to_file = new File(to)
      import java.nio.file._
      val src = new FileInputStream(from)
      Files.copy(src, to_file.toPath, StandardCopyOption.REPLACE_EXISTING)
    }
    catch {
      case _: FileNotFoundException => println("File not found.Check path to file.")
    }
  }
}

}
