import express from 'express';
import * as snippetController from '../controllers/snippetController';

import { verifyJWT } from '../middleware/verifyJWT';

const snippetRouter = express.Router();

snippetRouter
  .get('/discover', snippetController.handleGetPage)
  .post('/ids', snippetController.handleGetSnippetsByIDS)
  .use(verifyJWT)
  .get('/:id', snippetController.handleGetById)
  .post('/', snippetController.handleCreate)
  .put('/:id', snippetController.handleModify)
  .delete('/:id', snippetController.handleDelete);

export default snippetRouter;
