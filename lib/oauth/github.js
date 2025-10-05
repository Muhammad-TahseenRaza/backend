import { GitHub } from "arctic";
import dotenv from "dotenv";
dotenv.config();

export const github = new GitHub(
    process.env.GITHUB_CLIENT_ID,
    process.env.GITHUB_CLIENT_SECRET,
    `${process.env.FRONTEND_URL}/github/callback`,
)