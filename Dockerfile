# Dockerfile para o backend Node.js - Aniversário da Sophia
FROM node:18-alpine

# Diretório de trabalho
WORKDIR /app

# Copia os arquivos do backend
COPY backend/package*.json ./
COPY backend/server.js ./
COPY backend/public ./public

# Instala dependências
RUN npm install --production

# Variáveis de ambiente (Render injeta DATABASE_URL automaticamente)
ENV NODE_ENV=production

# Expõe a porta do serviço
EXPOSE 3000

# Comando para iniciar o servidor
CMD ["node", "server.js"]
