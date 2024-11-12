# La veille sur les cybermenaces

[![License: CC BY-NC-ND 4.0](https://img.shields.io/badge/License-CC%20BY--NC--ND%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-nd/4.0/)

## Description

Ce projet est une **veille automatisée sur les cybermenaces**, conçue pour surveiller, collecter et organiser des informations pertinentes concernant les menaces en cybersécurité. Le tableau de bord présente les dernières informations issues de diverses sources de flux RSS, ainsi que des indicateurs de compromission (IoCs) recueillis via l’API d’**AlienVault OTX**. 

Le tableau de bord est automatiquement mis à jour chaque jour à minuit (UTC) grâce à un workflow GitHub Actions. Ce projet est principalement destiné à des fins éducatives, et toute utilisation pour des projets similaires peut être considérée comme de la triche.

Accédez au tableau de bord à l'adresse suivante : [https://nav-mtl.github.io/la-veille/](https://nav-mtl.github.io/la-veille/)

## Fonctionnalités

- Collecte des dernières cybermenaces via les flux RSS de **CyberScoop**, **ThreatPost**, et **ExploitDB**.
- Surveillance et affichage des **adresses IP malveillantes**, des **URLs de phishing** et des **hashes malveillants** (MD5, SHA1, SHA256).
- Mise à jour automatique chaque jour à minuit (UTC) grâce à GitHub Actions.
- Interface utilisateur intuitive avec des sections dédiées aux flux RSS, aux IP et domaines malveillants, et aux hashes malveillants.

## Structure du Projet

Le projet est organisé comme suit :
- **Scripts Python** : Code pour extraire et organiser les données provenant des flux RSS et de l'API AlienVault OTX.
- **Tableau de bord GitHub Pages** : Présentation des données dans un tableau de bord visuel, accessible publiquement.
- **GitHub Actions** : Automatisation de la collecte des données et mise à jour du tableau de bord quotidiennement.

## Dépendances

- Python 3.x
- `requests` pour les appels API
- `feedparser` pour l’analyse des flux RSS

## Installation

1. **Clonez le dépôt :**
   ```bash
   git clone https://github.com/nav-mtl/la-veille.git
   cd la-veille
   
2. **Installez les dépendances :**
   ```bash
   pip install -r requirements.txt
   
3. **Installez les dépendances :**
   Ajoutez votre clé API AlienVault dans les GitHub Secrets sous le nom OTX_API_KEY.
   Ajoutez également GH_TOKEN si nécessaire pour les permissions de mise à jour via GitHub Actions.
   
5. **Exécutez le script manuellement pour tester la collecte de données :**
   ```bash
   python feed_script.py

## Automatisation avec GitHub Actions
- Ce projet utilise un workflow GitHub Actions pour exécuter automatiquement le script chaque jour à minuit UTC et mettre à jour le tableau de bord sur GitHub Pages.
- Cron job : cron: '0 0 * * *' - Exécute le workflow chaque jour à minuit UTC.
- URL du tableau de bord : https://nav-mtl.github.io/la-veille/

## Licence
- Ce projet est sous licence Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0). Vous êtes libre de partager ce projet, à condition de donner le crédit approprié et de ne pas l'utiliser à des fins commerciales. Toute utilisation pour des projets similaires peut être considérée comme de la triche.

## Avertissement pour les étudiants
- Ce projet est réalisé dans le cadre universitaire et toute copie ou utilisation non autorisée pour des projets éducatifs sera considérée comme de la triche. Assurez-vous de comprendre et de respecter les règles académiques.
