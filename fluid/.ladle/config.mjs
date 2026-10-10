/** @type {import('@ladle/react').UserConfig} */
export default {
  stories: 'src/**/*.stories.{ts,tsx}',
  defaultStory: 'claims-claimcard--supported',
  // Ladle mounts under the same path prefix the app uses, so relative assets
  // resolve identically inside and outside the app shell.
  base: '/fluid/',
};
