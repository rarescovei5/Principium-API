const allowedOrigins = [process.env.FRONTEND_PATH];
const corsOptions = {
  origin: (origin: any, callback: any) => {
    console.log(origin);
    if (allowedOrigins.includes(origin) || !origin) {
      return callback(null, true);
    }

    if (origin.startsWith('http://localhost:')) return callback(null, true);

    // For vscode snippets extension
    if (origin.startsWith('vscode-webview-resource://') || origin.startsWith('vscode-webview://')) {
      return callback(null, true);
    }

    callback(new Error('Not allowed by CORS'));
  },
  methods: ['POST', 'GET', 'PUT', 'DELETE'],
  credentials: true,
};
export default corsOptions;
