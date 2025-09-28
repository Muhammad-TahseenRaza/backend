ALTER TABLE `short_links` ADD `created_at` timestamp DEFAULT (now()) NOT NULL;--> statement-breakpoint
ALTER TABLE `short_links` ADD `updated_at` timestamp DEFAULT (now()) NOT NULL ON UPDATE CURRENT_TIMESTAMP;--> statement-breakpoint
ALTER TABLE `short_links` ADD `user_id` int NOT NULL;--> statement-breakpoint
ALTER TABLE `short_links` ADD CONSTRAINT `short_links_user_id_shortCode_unique` UNIQUE(`user_id`,`shortCode`);--> statement-breakpoint
ALTER TABLE `short_links` ADD CONSTRAINT `short_links_user_id_users_id_fk` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE cascade ON UPDATE no action;