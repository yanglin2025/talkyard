/**
 * Copyright (c) 2024 Talkyard Community
 * License: AGPL
 */
package talkyard.server.security

import com.lambdaworks.crypto.SCryptUtil
import org.mindrot.jbcrypt.BCrypt
import play.api.Logger

/**
 * 密码哈希迁移工具
 * 支持从 bcrypt 自动迁移到 scrypt
 */
object PasswordMigration {
  
  private val logger = Logger(this.getClass)
  
  /**
   * 验证密码，支持多种哈希格式
   */
  def verifyPassword(plainPassword: String, storedHash: String): Boolean = {
    try {
      if (isBcryptHash(storedHash)) {
        // bcrypt 格式
        BCrypt.checkpw(plainPassword, storedHash)
      } else if (storedHash.startsWith("scrypt:")) {
        // scrypt 格式（Talkyard 原生格式）
        val hashWithoutPrefix = storedHash.substring(7)
        SCryptUtil.check(plainPassword, hashWithoutPrefix)
      } else {
        // 未知格式
        logger.warn(s"Unknown password hash format: ${storedHash.take(10)}... [TyEUNKNPWDHASH]")
        false
      }
    } catch {
      case e: IllegalArgumentException =>
        logger.warn(s"Invalid hash format: ${e.getMessage} [TyEINVLDHASH]")
        false
      case e: Exception =>
        logger.error(s"Error verifying password: ${e.getMessage} [TyEPWDVERIFY]", e)
        false
    }
  }
  
  /**
   * 生成 scrypt 哈希（Talkyard 标准格式）
   */
  def generateScryptHash(plainPassword: String): String = {
    // 使用 Talkyard 的标准参数: N=16384, r=8, p=1
    "scrypt:" + SCryptUtil.scrypt(plainPassword, 16384, 8, 1)
  }
  
  /**
   * 检查是否需要迁移到 scrypt
   */
  def needsMigration(storedHash: String): Boolean = {
    isBcryptHash(storedHash)
  }
  
  /**
   * 检查是否为 bcrypt 哈希
   */
  def isBcryptHash(hash: String): Boolean = {
    hash.startsWith("$2a$") || 
    hash.startsWith("$2b$") || 
    hash.startsWith("$2y$")
  }
  
  /**
   * 获取哈希类型（用于日志）
   */
  def getHashType(storedHash: String): String = {
    if (storedHash.startsWith("$2a$")) "bcrypt-2a"
    else if (storedHash.startsWith("$2b$")) "bcrypt-2b"
    else if (storedHash.startsWith("$2y$")) "bcrypt-2y"
    else if (storedHash.startsWith("scrypt:")) "scrypt"
    else "unknown"
  }
}
