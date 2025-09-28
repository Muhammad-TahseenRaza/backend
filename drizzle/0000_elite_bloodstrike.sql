CREATE TABLE `short_links` (
	`id` int AUTO_INCREMENT NOT NULL,
	`shortCode` varchar(20) NOT NULL,
	`url` varchar(255) NOT NULL,
	CONSTRAINT `short_links_id` PRIMARY KEY(`id`)
);
