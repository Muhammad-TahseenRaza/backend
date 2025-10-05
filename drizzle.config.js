import { defineConfig } from 'drizzle-kit';
import dotenv from "dotenv";
dotenv.config();

export default defineConfig({
  out: './drizzle',
  schema: './drizzle/schema.js',
  dialect: 'mysql',
  dbCredentials: {
    host: 'localhost',    // Docker host ke liye
    port: 3307,          // Tumhara mapped port
    user: 'root',
    password: 'Kingkokl9@',
    database: 'url_shortener',
  },
});