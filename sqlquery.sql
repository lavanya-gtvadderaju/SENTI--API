
CREATE DATABASE senti_db;

USE senti_db;

-- Drop the tables if they exist before creating them (optional)
DROP TABLE IF EXISTS sentences;
DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    fullname VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS sentences (
    sentence_id INT PRIMARY KEY AUTO_INCREMENT,
    content TEXT NOT NULL,
    lowers TEXT NOT NULL,
    withoutstopword  TEXT NOT NULL,
    lemmatized_sentence TEXT NOT NULL,
    sentiment TEXT NOT NULL, 
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

select * from `users`;

select * from `sentences`;
