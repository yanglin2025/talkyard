/**
 * Copyright (c) 2024 Talkyard Community
 * License: AGPL
 */
package talkyard.server.security

import com.lambdaworks.crypto.SCryptUtil
import org.mindrot.jbcrypt.BCrypt
import play.api.Logger

/**
 * Password hash migration utility
 * Supports automatic migration from bcrypt to scrypt
 */
object PasswordMigration {
  
  private val logger = Logger(this.getClass)
  
  /**
   * Verify password, supports multiple hash formats
   */
  def verifyPassword(plainPassword: String, storedHash: String): Boolean = {
    try {
      if (isBcryptHash(storedHash)) {
        // bcrypt format
        BCrypt.checkpw(plainPassword, storedHash)
      } else if (storedHash.startsWith("scrypt:")) {
        // scrypt format (Talkyard native format)
        val hashWithoutPrefix = storedHash.substring(7)
        SCryptUtil.check(plainPassword, hashWithoutPrefix)
      } else {
        // Unknown format
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
   * Generate scrypt hash (Talkyard standard format)
   */
  def generateScryptHash(plainPassword: String): String = {
    // Use Talkyard standard parameters: N=16384, r=8, p=1
    "scrypt:" + SCryptUtil.scrypt(plainPassword, 16384, 8, 1)
  }
  
  /**
   * Check if migration to scrypt is needed
   */
  def needsMigration(storedHash: String): Boolean = {
    isBcryptHash(storedHash)
  }
  
  /**
   * Check if hash is bcrypt format
   */
  def isBcryptHash(hash: String): Boolean = {
    hash.startsWith("$2a$") || 
    hash.startsWith("$2b$") || 
    hash.startsWith("$2y$")
  }
  
  /**
   * Get hash type (for logging purposes)
   */
  def getHashType(storedHash: String): String = {
    if (storedHash.startsWith("$2a$")) "bcrypt-2a"
    else if (storedHash.startsWith("$2b$")) "bcrypt-2b"
    else if (storedHash.startsWith("$2y$")) "bcrypt-2y"
    else if (storedHash.startsWith("scrypt:")) "scrypt"
    else "unknown"
  }
}
