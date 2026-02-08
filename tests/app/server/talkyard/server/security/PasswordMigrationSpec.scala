/**
 * Copyright (c) 2024 Talkyard Community
 * License: AGPL
 */
package talkyard.server.security

import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.must.Matchers

class PasswordMigrationSpec extends AnyFreeSpec with Matchers {

  "PasswordMigration" - {
    
    "isBcryptHash" - {
      "should recognize bcrypt 2a hash" in {
        PasswordMigration.isBcryptHash("$2a$10$abcdefghijklmnopqrstuv") mustBe true
      }
      
      "should recognize bcrypt 2b hash" in {
        PasswordMigration.isBcryptHash("$2b$10$abcdefghijklmnopqrstuv") mustBe true
      }
      
      "should recognize bcrypt 2y hash" in {
        PasswordMigration.isBcryptHash("$2y$10$abcdefghijklmnopqrstuv") mustBe true
      }
      
      "should reject scrypt hash" in {
        PasswordMigration.isBcryptHash("scrypt:somehashhereblahblah") mustBe false
      }
      
      "should reject unknown hash format" in {
        PasswordMigration.isBcryptHash("unknownformat") mustBe false
      }
    }
    
    "needsMigration" - {
      "should return true for bcrypt hash" in {
        PasswordMigration.needsMigration("$2a$10$abcdefghijklmnopqrstuv") mustBe true
      }
      
      "should return false for scrypt hash" in {
        PasswordMigration.needsMigration("scrypt:somehashhereblahblah") mustBe false
      }
    }
    
    "getHashType" - {
      "should identify bcrypt-2a" in {
        PasswordMigration.getHashType("$2a$10$abc") mustBe "bcrypt-2a"
      }
      
      "should identify bcrypt-2b" in {
        PasswordMigration.getHashType("$2b$10$abc") mustBe "bcrypt-2b"
      }
      
      "should identify bcrypt-2y" in {
        PasswordMigration.getHashType("$2y$10$abc") mustBe "bcrypt-2y"
      }
      
      "should identify scrypt" in {
        PasswordMigration.getHashType("scrypt:abc") mustBe "scrypt"
      }
      
      "should return unknown for unrecognized format" in {
        PasswordMigration.getHashType("blahblah") mustBe "unknown"
      }
    }
    
    "generateScryptHash" - {
      "should generate scrypt hash with correct prefix" in {
        val password = "test123"
        val hash = PasswordMigration.generateScryptHash(password)
        hash must startWith("scrypt:")
      }
      
      "should generate different hashes for same password" in {
        val password = "test123"
        val hash1 = PasswordMigration.generateScryptHash(password)
        val hash2 = PasswordMigration.generateScryptHash(password)
        hash1 must not equal hash2
      }
    }
    
    "verifyPassword" - {
      "should verify correct scrypt password" in {
        val password = "myPassword123"
        val hash = PasswordMigration.generateScryptHash(password)
        PasswordMigration.verifyPassword(password, hash) mustBe true
      }
      
      "should reject incorrect scrypt password" in {
        val password = "myPassword123"
        val hash = PasswordMigration.generateScryptHash(password)
        PasswordMigration.verifyPassword("wrongPassword", hash) mustBe false
      }
      
      "should verify correct bcrypt password" in {
        val password = "myPassword123"
        // This is a pre-computed bcrypt hash for "myPassword123" using cost 10
        val bcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        PasswordMigration.verifyPassword(password, bcryptHash) mustBe true
      }
      
      "should reject incorrect bcrypt password" in {
        val bcryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        PasswordMigration.verifyPassword("wrongPassword", bcryptHash) mustBe false
      }
      
      "should handle invalid hash format gracefully" in {
        PasswordMigration.verifyPassword("password", "invalidhash") mustBe false
      }
    }
  }
}
