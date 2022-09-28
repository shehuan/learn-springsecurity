CREATE TABLE `oauth_client_details` (
  `client_id` varchar(50) NOT NULL,
  `client_secret` varchar(256) DEFAULT NULL,
  `resource_ids` varchar(50) DEFAULT NULL,
  `scope` varchar(256) DEFAULT NULL,
  `authorized_grant_types` varchar(256) DEFAULT NULL,
  `web_server_redirect_uri` varchar(256) DEFAULT NULL,
  `authorities` varchar(256) DEFAULT NULL,
  `access_token_validity` int DEFAULT NULL,
  `refresh_token_validity` int DEFAULT NULL,
  `additional_information` varchar(4096) DEFAULT NULL,
  `autoapprove` varchar(256) DEFAULT NULL,
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


INSERT INTO `security`.oauth_client_details (client_id,client_secret,resource_ids,`scope`,authorized_grant_types,web_server_redirect_uri,authorities,access_token_validity,refresh_token_validity,additional_information,autoapprove) VALUES
	 ('my_client','$2a$10$jZNjCQjEIS2XkjN8/mBgOO20q71yWuA8MOhCtf5dYXcaJBZOzEL3G',NULL,'read:user,read:msg','authorization_code,refresh_token,implicit,password,client_credentials','http://client.shehuan.com:7008/login/oauth2/code/shehuan',NULL,60,120,NULL,'false');