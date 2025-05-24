CREATE DATABASE `principium`;
USE `principium`;

CREATE TABLE `users` (
    `id`            CHAR(36) PRIMARY KEY DEFAULT (UUID()), 
    `first_name`    VARCHAR(50)  NOT NULL,
    `last_name`     VARCHAR(50)  NOT NULL,
    `email`         VARCHAR(100) UNIQUE NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `avatar_url`    VARCHAR(255),
    `created_at`    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE `code_snippets` (
    `id`          CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    `user_id`     CHAR(36) NOT NULL,
    `title`       VARCHAR(100) NOT NULL,
    `description` TEXT,
    `code`        BLOB NOT NULL,
    `language`    VARCHAR(50) NOT NULL,
    `created_at`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,

    INDEX `idx_language` (`language`)
);
