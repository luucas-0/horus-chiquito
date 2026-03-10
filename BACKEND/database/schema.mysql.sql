CREATE TABLE `Users`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `email` VARCHAR(255) NOT NULL,
    `username` VARCHAR(255) NULL,
    `full_name` VARCHAR(255) NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `is_active` BOOLEAN NOT NULL DEFAULT 1,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP(), `last_login` TIMESTAMP NULL);
ALTER TABLE
    `Users` ADD UNIQUE `users_email_unique`(`email`);
ALTER TABLE
    `Users` ADD UNIQUE `users_username_unique`(`username`);
CREATE TABLE `UserProfiles`(
    `user_id` INT NOT NULL,
    `nombre_completo` VARCHAR(255) NOT NULL,
    `cedula` VARCHAR(50) NOT NULL,
    `telefono` VARCHAR(50) NULL,
    `pais` VARCHAR(100) NULL,
    `ciudad` VARCHAR(100) NULL,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP(), PRIMARY KEY(`user_id`));
ALTER TABLE
    `UserProfiles` ADD UNIQUE `userprofiles_cedula_unique`(`cedula`);
CREATE TABLE `Roles`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(50) NOT NULL,
    `description` VARCHAR(255) NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `Roles` ADD UNIQUE `roles_name_unique`(`name`);
CREATE TABLE `UserRoles`(
    `user_id` INT NOT NULL,
    `role_id` INT NOT NULL,
    `assigned_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP(), PRIMARY KEY(`user_id`, `role_id`));
CREATE TABLE `Simulations`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `scan_type` ENUM(
        'network_detect',
        'discover',
        'deep_scan'
    ) NOT NULL,
    `target_subnet` VARCHAR(50) NULL,
    `target_ip` VARCHAR(45) NULL,
    `status` ENUM(
        'pending',
        'running',
        'completed',
        'failed'
    ) NOT NULL DEFAULT 'pending',
    `start_time` TIMESTAMP NULL,
    `end_time` TIMESTAMP NULL,
    `scan_time_seconds` INT NULL,
    `nmap_version` VARCHAR(50) NULL,
    `nmap_command` TEXT NULL,
    `error_message` TEXT NULL,
    `json_response` LONGTEXT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `Simulations` ADD INDEX `simulations_user_id_created_at_index`(`user_id`, `created_at`);
ALTER TABLE
    `Simulations` ADD INDEX `simulations_target_ip_index`(`target_ip`);
ALTER TABLE
    `Simulations` ADD INDEX `simulations_status_index`(`status`);
CREATE TABLE `Hosts`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `simulation_id` INT NOT NULL,
    `user_id` INT NOT NULL,
    `ip_address` VARCHAR(45) NOT NULL,
    `mac_address` VARCHAR(17) NULL,
    `mac_vendor` VARCHAR(255) NULL,
    `hostname` VARCHAR(255) NULL,
    `os_detection` VARCHAR(255) NULL,
    `device_type` VARCHAR(100) NULL,
    `discovered_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP(), `last_scanned_at` TIMESTAMP NULL);
ALTER TABLE
    `Hosts` ADD INDEX `hosts_user_id_ip_address_index`(`user_id`, `ip_address`);
ALTER TABLE
    `Hosts` ADD INDEX `hosts_simulation_id_index`(`simulation_id`);
ALTER TABLE
    `Hosts` ADD INDEX `hosts_ip_address_index`(`ip_address`);
CREATE TABLE `Ports`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `host_id` INT NOT NULL,
    `port_number` INT NOT NULL,
    `protocol` ENUM('tcp', 'udp') NOT NULL DEFAULT 'tcp',
    `state` VARCHAR(50) NOT NULL,
    `service` VARCHAR(100) NULL,
    `product` VARCHAR(255) NULL,
    `version` VARCHAR(100) NULL,
    `cpe` VARCHAR(255) NULL,
    `extra_info` TEXT NULL,
    `discovered_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `Ports` ADD INDEX `ports_port_number_service_index`(`port_number`, `service`);
ALTER TABLE
    `Ports` ADD INDEX `ports_host_id_index`(`host_id`);
CREATE TABLE `Vulnerabilities`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `simulation_id` INT NOT NULL,
    `host_id` INT NOT NULL,
    `port_id` INT NULL,
    `script_id` VARCHAR(255) NOT NULL,
    `severity` ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    `output` LONGTEXT NULL,
    `detected_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `Vulnerabilities` ADD INDEX `vulnerabilities_simulation_id_index`(`simulation_id`);
ALTER TABLE
    `Vulnerabilities` ADD INDEX `vulnerabilities_host_id_index`(`host_id`);
ALTER TABLE
    `Vulnerabilities` ADD INDEX `vulnerabilities_severity_index`(`severity`);
CREATE TABLE `CredentialTests`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `simulation_id` INT NOT NULL,
    `host_id` INT NOT NULL,
    `port_id` INT NOT NULL,
    `user_id` INT NOT NULL,
    `service` VARCHAR(100) NOT NULL,
    `status` VARCHAR(100) NOT NULL,
    `found_username` VARCHAR(255) NULL,
    `found_password` INT NULL,
    `risk_score` TINYINT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `CredentialTests` ADD INDEX `credentialtests_simulation_id_index`(`simulation_id`);
ALTER TABLE
    `CredentialTests` ADD INDEX `credentialtests_user_id_index`(`user_id`);
ALTER TABLE
    `CredentialTests` ADD INDEX `credentialtests_service_index`(`service`);
CREATE TABLE `Reports`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `simulation_id` INT NOT NULL,
    `user_id` INT NOT NULL,
    `filename` VARCHAR(255) NOT NULL,
    `path` VARCHAR(1024) NOT NULL,
    `size_bytes` BIGINT NULL,
    `version` INT NOT NULL DEFAULT 1,
    `generated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `Reports` ADD INDEX `reports_simulation_id_index`(`simulation_id`);
ALTER TABLE
    `Reports` ADD INDEX `reports_user_id_index`(`user_id`);
CREATE TABLE `AuditLog`(
    `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT NOT NULL,
    `action` VARCHAR(100) NOT NULL,
    `resource_type` VARCHAR(50) NULL,
    `resource_id` INT NULL,
    `ip_address` VARCHAR(45) NULL,
    `user_agent` VARCHAR(512) NULL,
    `details` JSON NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP());
ALTER TABLE
    `AuditLog` ADD INDEX `auditlog_user_id_created_at_index`(`user_id`, `created_at`);
ALTER TABLE
    `AuditLog` ADD INDEX `auditlog_action_index`(`action`);
ALTER TABLE
    `Simulations` ADD CONSTRAINT `simulations_user_id_foreign` FOREIGN KEY(`user_id`) REFERENCES `Users`(`id`);
ALTER TABLE
    `CredentialTests` ADD CONSTRAINT `credentialtests_port_id_foreign` FOREIGN KEY(`port_id`) REFERENCES `Ports`(`id`);
ALTER TABLE
    `Reports` ADD CONSTRAINT `reports_simulation_id_foreign` FOREIGN KEY(`simulation_id`) REFERENCES `Simulations`(`id`);
ALTER TABLE
    `Ports` ADD CONSTRAINT `ports_host_id_foreign` FOREIGN KEY(`host_id`) REFERENCES `Hosts`(`id`);
ALTER TABLE
    `Hosts` ADD CONSTRAINT `hosts_user_id_foreign` FOREIGN KEY(`user_id`) REFERENCES `Users`(`id`);
ALTER TABLE
    `Hosts` ADD CONSTRAINT `hosts_simulation_id_foreign` FOREIGN KEY(`simulation_id`) REFERENCES `Simulations`(`id`);
ALTER TABLE
    `CredentialTests` ADD CONSTRAINT `credentialtests_user_id_foreign` FOREIGN KEY(`user_id`) REFERENCES `Users`(`id`);
ALTER TABLE
    `UserRoles` ADD CONSTRAINT `userroles_role_id_foreign` FOREIGN KEY(`role_id`) REFERENCES `Roles`(`id`);
ALTER TABLE
    `CredentialTests` ADD CONSTRAINT `credentialtests_simulation_id_foreign` FOREIGN KEY(`simulation_id`) REFERENCES `Simulations`(`id`);
ALTER TABLE
    `UserProfiles` ADD CONSTRAINT `userprofiles_user_id_foreign` FOREIGN KEY(`user_id`) REFERENCES `Users`(`id`);
ALTER TABLE
    `Vulnerabilities` ADD CONSTRAINT `vulnerabilities_port_id_foreign` FOREIGN KEY(`port_id`) REFERENCES `Ports`(`id`);
ALTER TABLE
    `Vulnerabilities` ADD CONSTRAINT `vulnerabilities_host_id_foreign` FOREIGN KEY(`host_id`) REFERENCES `Hosts`(`id`);
ALTER TABLE
    `UserRoles` ADD CONSTRAINT `userroles_user_id_foreign` FOREIGN KEY(`user_id`) REFERENCES `Users`(`id`);
ALTER TABLE
    `Reports` ADD CONSTRAINT `reports_user_id_foreign` FOREIGN KEY(`user_id`) REFERENCES `Users`(`id`);
ALTER TABLE
    `AuditLog` ADD CONSTRAINT `auditlog_user_id_foreign` FOREIGN KEY(`user_id`) REFERENCES `Users`(`id`);
ALTER TABLE
    `CredentialTests` ADD CONSTRAINT `credentialtests_host_id_foreign` FOREIGN KEY(`host_id`) REFERENCES `Hosts`(`id`);
ALTER TABLE
    `Vulnerabilities` ADD CONSTRAINT `vulnerabilities_simulation_id_foreign` FOREIGN KEY(`simulation_id`) REFERENCES `Simulations`(`id`);
-- Optional table used by api/services/db.service.js when available.
-- If you skip this table, AI analysis is stored in Simulations.json_response.
CREATE TABLE IF NOT EXISTS `AIAnalysisResults` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `simulation_id` INT NOT NULL,
  `model_version` VARCHAR(100) NULL,
  `risk_score_global` TINYINT NULL,
  `severity_summary` JSON NULL,
  `findings` LONGTEXT NULL,
  `recommendations` LONGTEXT NULL,
  `analyzed_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `ai_analysis_results_simulation_id_unique` (`simulation_id`),
  CONSTRAINT `ai_analysis_results_simulation_id_foreign`
    FOREIGN KEY (`simulation_id`) REFERENCES `Simulations`(`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);
