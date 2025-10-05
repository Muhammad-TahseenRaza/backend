# 1️⃣ Base image
FROM node:18

# 2️⃣ Working directory
WORKDIR /app

# 3️⃣ Copy package.json first (for caching npm install)
COPY package*.json ./

# 4️⃣ Install dependencies
RUN npm install

# 5️⃣ Copy rest of the project
COPY . .

# 6️⃣ Expose port
EXPOSE 3000

# 7️⃣ Start command
CMD ["npm", "start"]