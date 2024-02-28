# Build de l'image pour la base de données PostgreSQL
docker build -t mon_postgresql_db -f Dockerfile.db .

# Lancement du conteneur de la base de données
docker run -d -p 5432:5432 --name mon_postgresql_db mon_postgresql_db
