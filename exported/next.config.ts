import type { NextConfig } from "next";
 
const nextConfig: NextConfig = {
 
  reactStrictMode: false,
  /* config options here */
  // appDir: true,

  eslint: {
    ignoreDuringBuilds: true,
  },

  typescript: {
    ignoreBuildErrors: true,
  },
};
 
export default nextConfig;