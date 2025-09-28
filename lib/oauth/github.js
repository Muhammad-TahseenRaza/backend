import { GitHub } from "arctic";

export const github = new GitHub(
    process.env.GITHUB_CLIENT_ID,
    process.env.GITHUB_CLIENT_SECRET,
    `${process.env.FRONTEND_URL}/github/callback`,
)