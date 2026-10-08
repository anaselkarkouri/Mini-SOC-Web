-- Mini-SOC Web — M1 VulnShop
-- Base de données volontairement vulnérable et fictive.
-- À importer dans MySQL/MariaDB via phpMyAdmin ou mysql CLI.

CREATE DATABASE IF NOT EXISTS minisoc_shop
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE minisoc_shop;

SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS http_logs;
DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS categories;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS = 1;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    password VARCHAR(120) NOT NULL,
    full_name VARCHAR(160) NOT NULL,
    email VARCHAR(180) NOT NULL,
    role ENUM('admin', 'manager', 'seller', 'customer') NOT NULL DEFAULT 'customer',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    description TEXT
) ENGINE=InnoDB;

CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category_id INT,
    name VARCHAR(180) NOT NULL,
    slug VARCHAR(220) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    old_price DECIMAL(10,2) NULL,
    image VARCHAR(255) NOT NULL,
    short_description VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    featured TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_products_category FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE reviews (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_id INT NOT NULL,
    author_name VARCHAR(160) NOT NULL,
    rating TINYINT NOT NULL DEFAULT 5,
    comment TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_reviews_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_code VARCHAR(60) NOT NULL UNIQUE,
    user_id INT NULL,
    customer_name VARCHAR(180) NOT NULL,
    email VARCHAR(180) NOT NULL,
    phone VARCHAR(50) NOT NULL,
    address TEXT NOT NULL,
    notes TEXT,
    total_amount DECIMAL(10,2) NOT NULL,
    status ENUM('processing', 'shipped', 'delivered', 'cancelled') NOT NULL DEFAULT 'processing',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_orders_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE order_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NULL,
    quantity INT NOT NULL DEFAULT 1,
    unit_price DECIMAL(10,2) NOT NULL,
    CONSTRAINT fk_items_order FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    CONSTRAINT fk_items_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Module M2 : table de collecte des logs HTTP (Omar Babba)
CREATE TABLE http_logs (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    timestamp     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure de la requete',
    ip_source     VARCHAR(45)   NOT NULL                            COMMENT 'Adresse IP source de l utilisateur ou attaquant',
    method        VARCHAR(10)   NOT NULL                            COMMENT 'Methode HTTP : GET ou POST',
    url           VARCHAR(512)  NOT NULL                            COMMENT 'Page PHP ciblee par la requete',
    params        TEXT                                              COMMENT 'Parametres GET et POST en JSON (prefixes GET_ / POST_)',
    user_agent    VARCHAR(512)                                      COMMENT 'Navigateur ou outil utilise (sqlmap, Hydra, curl, etc.)',
    response_code SMALLINT      NOT NULL DEFAULT 200               COMMENT 'Code HTTP retourne par l application',
    processed     TINYINT(1)    NOT NULL DEFAULT 0                  COMMENT '0 = non analyse, 1 = traite par le Mini-SIEM'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


INSERT INTO users (username, password, full_name, email, role) VALUES
('admin', 'admin123', 'Administrateur Atlas', 'admin@atlas-minishop.local', 'admin'),
('manager', 'manager', 'Nadia Manager', 'manager@atlas-minishop.local', 'manager'),
('seller', 'password', 'Youssef Seller', 'seller@atlas-minishop.local', 'seller'),
('alice', '123456', 'Alice Client', 'alice@example.local', 'customer'),
('bob', 'qwerty', 'Bob Client', 'bob@example.local', 'customer');

INSERT INTO categories (name, description) VALUES
('Smartphones', 'Téléphones et accessoires mobiles.'),
('Ordinateurs', 'PC portables, mini-PC et périphériques.'),
('Maison connectée', 'Objets connectés pour le quotidien.'),
('Accessoires', 'Chargeurs, câbles, supports et gadgets.');

INSERT INTO products (category_id, name, slug, price, old_price, image, short_description, description, stock, featured) VALUES
(1, 'AtlasPhone Lite X2', 'atlasphone-lite-x2', 2490.00, 2890.00, 'assets/img/phone.svg', 'Smartphone 6.5 pouces avec batterie longue durée.', 'Un téléphone fictif pensé pour les démonstrations de catalogue : grand écran, autonomie solide et design compact.', 18, 1),
(1, 'Coque Rugged AtlasPhone', 'coque-rugged-atlasphone', 149.00, NULL, 'assets/img/case.svg', 'Coque antichoc compatible AtlasPhone.', 'Protection renforcée, texture antidérapante et finition mate.', 52, 1),
(2, 'AtlasBook 14 Air', 'atlasbook-14-air', 6890.00, 7490.00, 'assets/img/laptop.svg', 'PC portable léger pour travail et études.', 'Ordinateur fictif avec écran 14 pouces, clavier confortable et stockage SSD.', 9, 1),
(2, 'Clavier Compact Pro', 'clavier-compact-pro', 390.00, NULL, 'assets/img/keyboard.svg', 'Clavier compact sans fil pour bureau.', 'Clavier AZERTY compact, touches silencieuses et connexion Bluetooth.', 31, 0),
(3, 'Caméra Maison 360', 'camera-maison-360', 690.00, 850.00, 'assets/img/camera.svg', 'Caméra connectée avec vision panoramique.', 'Caméra de démonstration avec vue 360°, mode nuit et alertes locales fictives.', 14, 1),
(3, 'Ampoule SmartColor E27', 'ampoule-smartcolor-e27', 129.00, NULL, 'assets/img/bulb.svg', 'Ampoule connectée multicolore.', 'Éclairage RGB fictif avec scénarios et réglage d’intensité.', 80, 1),
(4, 'PowerBank Atlas 20K', 'powerbank-atlas-20k', 320.00, 399.00, 'assets/img/powerbank.svg', 'Batterie externe 20 000 mAh.', 'PowerBank fictif avec double sortie USB et charge rapide.', 40, 1),
(4, 'Hub USB-C Multiport', 'hub-usb-c-multiport', 280.00, NULL, 'assets/img/hub.svg', 'Hub USB-C HDMI, USB et Ethernet.', 'Accessoire compact pour postes de travail mobiles.', 27, 0);

INSERT INTO reviews (product_id, author_name, rating, comment, created_at) VALUES
(1, 'Meryem', 5, 'Très bon rapport qualité/prix pour une boutique de démonstration.', NOW() - INTERVAL 4 DAY),
(1, 'Hamza', 4, 'Design propre et livraison fictive rapide.', NOW() - INTERVAL 2 DAY),
(3, 'Omar', 5, 'Parfait pour les cours et les présentations.', NOW() - INTERVAL 1 DAY),
(5, 'Salma', 4, 'Interface claire, produit conforme à la description.', NOW() - INTERVAL 8 HOUR);

INSERT INTO orders (order_code, user_id, customer_name, email, phone, address, notes, total_amount, status, created_at) VALUES
('AMS-20250101-1001', 4, 'Alice Client', 'alice@example.local', '0600000001', '12 Rue Demo, Casablanca', 'Livraison matin.', 2515.00, 'delivered', NOW() - INTERVAL 12 DAY),
('AMS-20250102-2002', 5, 'Bob Client', 'bob@example.local', '0600000002', '25 Avenue Test, Rabat', 'Appeler avant livraison.', 715.00, 'processing', NOW() - INTERVAL 2 DAY);

INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES
(1, 1, 1, 2490.00),
(2, 5, 1, 690.00);

-- Module M3 : tables de detection et enrichissement MITRE ATT&CK (Fadoua El-Allagui)
CREATE TABLE alerts (
    id                   INT AUTO_INCREMENT PRIMARY KEY,
    timestamp            DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure de detection de l attaque',
    log_id               INT           NOT NULL                            COMMENT 'Reference vers http_logs.id (log source)',
    attack_type          VARCHAR(100)  NOT NULL                            COMMENT 'Type : SQL Injection | Cross-Site Scripting | Brute Force',
    severity             VARCHAR(20)   NOT NULL                            COMMENT 'Gravite : LOW | MEDIUM | HIGH | CRITICAL',
    description          TEXT                                              COMMENT 'Description lisible de l attaque detectee',
    payload              TEXT                                              COMMENT 'Contenu suspect envoye par l attaquant',
    source_ip            VARCHAR(45)   NOT NULL                            COMMENT 'Adresse IP de l attaquant',
    url                  VARCHAR(255)  NOT NULL                            COMMENT 'Page web ciblee par l attaque',
    mitre_id             VARCHAR(20)                                       COMMENT 'Identifiant MITRE ATT&CK ex: T1190',
    mitre_tactic         VARCHAR(100)                                      COMMENT 'Tactique MITRE ex: Initial Access',
    mitre_technique      VARCHAR(200)                                      COMMENT 'Technique MITRE ex: Exploit Public-Facing Application',
    recommended_response TEXT                                              COMMENT 'Action recommandee pour traiter l attaque',
    status               VARCHAR(30)   NOT NULL DEFAULT 'nouveau'          COMMENT 'Statut : nouveau | en_cours | resolu | faux_positif',
    UNIQUE KEY uniq_alert_log_attack_ip (log_id, attack_type, source_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
 
CREATE TABLE threat_score (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    timestamp    DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP  COMMENT 'Date et heure du calcul du score',
    score_global INT         NOT NULL DEFAULT 0                  COMMENT 'Score calcule sur les 10 dernieres minutes',
    niveau       VARCHAR(20) NOT NULL                            COMMENT 'Niveau : LOW | MEDIUM | HIGH | CRITICAL',
    detail       TEXT                                            COMMENT 'Detail du calcul par attaque et par IP',
    score_total  INT         NOT NULL DEFAULT 0                  COMMENT 'Score cumulatif total depuis le debut'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
 
