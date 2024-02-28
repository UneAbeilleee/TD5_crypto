-- Création de la base de données
CREATE DATABASE password_db;

-- Utilisation de la base de données
\c password_db;

-- Création de la table utilisateur
CREATE TABLE utilisateur (
    id UUID PRIMARY KEY,
    username VARCHAR(255),
    hashed_password VARCHAR(255)
);

