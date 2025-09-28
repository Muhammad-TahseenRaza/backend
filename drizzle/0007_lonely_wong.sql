ALTER TABLE `is_email_valid` RENAME COLUMN `used` TO `created_at`;--> statement-breakpoint
ALTER TABLE `is_email_valid` MODIFY COLUMN `created_at` timestamp NOT NULL DEFAULT (now());