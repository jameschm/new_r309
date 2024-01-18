CREATE USER 'toto'@'localhost' IDENTIFIED BY 'toto';

CREATE DATABASE sae32;

USE sae32;

CREATE TABLE users ( 
    id INT AUTO_INCREMENT PRIMARY KEY, 
    nom VARCHAR(255) NOT NULL, 
    prenom VARCHAR(255) NOT NULL, 
    identifiant VARCHAR(255) NOT NULL UNIQUE, 
    mot_de_passe CHAR(60) NOT NULL, 
    adresse_ip VARCHAR(45) NOT NULL, 
    adresse_mail VARCHAR(255) NOT NULL UNIQUE, 
    statut ENUM('active', 'inactive', 'banned') NOT NULL DEFAULT 'active' 
);

CREATE TABLE serv ( 
    id INT AUTO_INCREMENT PRIMARY KEY, 
    login VARCHAR(255) NOT NULL, 
    mot_de_passe CHAR(60) NOT NULL
); 

CREATE TABLE mess ( 
    id INT AUTO_INCREMENT PRIMARY KEY, 
    utilisateur_id INT NOT NULL, 
    message_texte TEXT NOT NULL, 
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, 
    topic VARCHAR(255) NOT NULL, 
    adresse_ip VARCHAR(45) NOT NULL, 
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id) 
); 

CREATE TABLE rights ( 
    id INT AUTO_INCREMENT PRIMARY KEY, 
    utilisateur_id INT NOT NULL, 
    topic VARCHAR(255) NOT NULL, 
    UNIQUE KEY utilisateur_topic_unique (utilisateur_id, topic),
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id)
); 

CREATE TABLE sanct ( 
    id INT AUTO_INCREMENT PRIMARY KEY, 
    utilisateur_id INT NULL, 
    adresse_ip VARCHAR(45) NULL, 
    type_sanction ENUM('ban', 'kick') NOT NULL, 
    date_sanction TIMESTAMP DEFAULT CURRENT_TIMESTAMP, 
    date_fin_sanction TIMESTAMP DEFAULT NULL,  
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id) 
); 

GRANT ALL PRIVILEGES ON sae32.* TO 'toto'; 