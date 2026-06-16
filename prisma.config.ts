import 'dotenv/config';
import { defineConfig, env } from '@prisma/config';

export default defineConfig({
  // Tell Prisma exactly where the schema is located
  schema: './prisma/schema.prisma',
  datasource: {
    // Use Prisma's native env() helper to securely grab the URL
    url: env('DATABASE_URL'),
  },
});