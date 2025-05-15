import express from 'express';
import { CodeSnippet } from '../types/CodeSnippet';
import pool from '../model/db';
import zlib from 'zlib';
import { AuthenticatedRequest } from '../types/AuthenticatedRequest';

const supportedLanguages = new Set([
  'apache',
  'arduino',
  'bash',
  'c',
  'cpp',
  'csharp',
  'css',
  'dart',
  'django',
  'dockerfile',
  'elixir',
  'excel',
  'go',
  'graphql',
  'http',
  'java',
  'javascript',
  'json',
  'kotlin',
  'lua',
  'makefile',
  'markdown',
  'nginx',
  'php',
  'powershell',
  'python',
  'ruby',
  'rust',
  'scss',
  'shell',
  'sql',
  'swift',
  'typescript',
  'wasm',
  'xml',
]);

// Example usage:
function isLanguageSupported(lang: string): boolean {
  return supportedLanguages.has(lang.toLowerCase());
}

const decompressCode = (buffer: Buffer | string): string => {
  if (!buffer || typeof buffer === 'string') return buffer;
  return zlib.gunzipSync(buffer).toString();
};

const handleGetPage = async (req: express.Request, res: express.Response) => {
  // Get Filters
  const languageFilter = req.query.language as string | undefined;
  const titleFilter = req.query.title as string | undefined;

  if (languageFilter && !isLanguageSupported(languageFilter)) {
    res.status(400).json({ error: 'Unsupported language filter.' });
    return;
  }

  // Base queries
  let countQuery = 'SELECT COUNT(*) AS total FROM `code_snippets`';
  let dataQuery = 'SELECT `id`, `title`, `description`, `code`, `language` FROM `code_snippets`';
  const queryParams: any[] = [];

  // Add Filters
  const whereClauses: string[] = [];
  if (languageFilter) {
    whereClauses.push('`language` = ?');
    queryParams.push(languageFilter);
  }
  if (titleFilter) {
    whereClauses.push('`title` LIKE ?');
    queryParams.push(`%${titleFilter}%`);
  }
  if (whereClauses.length > 0) {
    const whereSQL = ' WHERE ' + whereClauses.join(' AND ');
    countQuery += whereSQL;
    dataQuery += whereSQL;
  }

  // Pagination defaults
  const DEFAULT_PAGE = 1;
  const DEFAULT_LIMIT = 12;

  const page = parseInt(req.query.page as string) || DEFAULT_PAGE;
  const limit = parseInt(req.query.limit as string) || DEFAULT_LIMIT;

  const offset = (page - 1) * limit;

  // Add LIMIT and OFFSET to data query
  dataQuery += ' LIMIT ? OFFSET ?';
  queryParams.push(limit, offset);

  try {
    const [countResult] = await pool.query(countQuery, queryParams.slice(0, queryParams.length - 2));
    const totalRecords = (countResult as any)[0].total;

    // Execute data query
    const [data] = await pool.query(dataQuery, queryParams);

    const totalPages = Math.ceil(totalRecords / limit);

    const snippets = (data as CodeSnippet[]).map((snippet) => ({
      ...snippet,
      code: decompressCode(snippet.code),
    }));

    res.status(200).json({
      totalRecords,
      totalPages,
      currentPage: page,
      records: snippets,
    });
  } catch (err) {
    console.error('Database query error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
};
const handleGetSnippetsByIDS = async (req: express.Request, res: express.Response) => {
  const q = 'SELECT `id`, `title`, `description`, `code`, `language` FROM `code_snippets` WHERE `id` IN (?);';
  const ids = req.body.ids;

  if (!Array.isArray(ids) || ids.length === 0) {
    res.status(400).json({ error: 'IDs must be a non-empty array.' });
    return;
  }

  try {
    const [data] = await pool.query(q, [ids]);

    const snippets = (data as CodeSnippet[]).map((snippet) => ({
      ...snippet,
      code: decompressCode(snippet.code),
    }));

    res.status(200).json(snippets);
  } catch (error) {
    console.error('SQL error:', error);
    res.status(500).json({ error: 'Something went wrong with the database.' });
  }
};
const handleGetById = async (req: AuthenticatedRequest, res: express.Response) => {
  const q = 'SELECT * FROM `code_snippets` WHERE `id` = ?';
  const id = req.params.id;

  try {
    const [data] = await pool.query(q, [id]);
    const d = data as CodeSnippet[];

    if (d.length === 0) {
      res.sendStatus(404);
      return;
    }

    const codeSnippet = d[0];

    res.status(200).json({
      ...codeSnippet,
      code: decompressCode(codeSnippet.code),
      isAuthor: req.user?.id === parseFloat(codeSnippet.user_id),
    });
    return;
  } catch (error) {
    console.error('SQL error:', error);
    res.status(500).json({ error: 'Something went wrong with the database.' });

    return;
  }
};
const handleCreate = async (req: AuthenticatedRequest, res: express.Response) => {
  const q = 'INSERT INTO `code_snippets` (`user_id`, `title`, `description`, `code`, `language`) VALUES (?);';
  const snippet: Partial<CodeSnippet> = req.body;

  if (!req.user?.id) {
    res.status(401).json({ error: 'User not authenticated.' });
    return;
  }

  if (!snippet.title || !snippet.description || !snippet.code || !snippet.language) {
    res.status(400).json({ error: 'Missing required fields.' });
    return;
  }

  if (!isLanguageSupported(snippet.language)) {
    res.status(400).json({ error: 'Unsported language' });
    return;
  }

  const compressedCode = zlib.gzipSync(snippet.code.trim());
  const values = [req.user.id, snippet.title.trim(), snippet.description.trim(), compressedCode, snippet.language];

  try {
    await pool.query(q, [values]);
    res.status(200).json({ message: 'Snippet created successfully.' });
  } catch (error) {
    console.error('SQL error:', error);
    res.status(500).json({ error: 'Something went wrong with the database.' });
  }
};
const handleModify = async (req: AuthenticatedRequest, res: express.Response) => {
  const q =
    'UPDATE `code_snippets` SET `title` = ?, `description` = ?, `code` = ?, `language` = ? WHERE `id` = ? AND `user_id` = ?';
  const updatedSnippet: Partial<CodeSnippet> = req.body;

  if (!req.user?.id) {
    res.status(401).json({ error: 'User not authenticated.' });
    return;
  } else if (!updatedSnippet.title || !updatedSnippet.description || !updatedSnippet.code || !updatedSnippet.language) {
    res.status(400).json({ error: 'Missing required fields.' });
    return;
  }
  if (!isLanguageSupported(updatedSnippet.language)) {
    res.status(400).json({ error: 'Unsported language' });
    return;
  }

  try {
    const values = [
      updatedSnippet.title.trim(),
      updatedSnippet.description.trim(),
      zlib.gzipSync(updatedSnippet.code.trim()),
      updatedSnippet.language,
      req.params.id,
      req.user.id,
    ];
    await pool.query(q, values);
    res.status(200).json({ message: 'Snippet modified successfully.' });
  } catch (error) {
    console.error('SQL error:', error);
    res.status(500).json({ error: 'Something went wrong with the database.' });

    return;
  }
};
const handleDelete = async (req: AuthenticatedRequest, res: express.Response) => {
  const q = 'DELETE FROM `code_snippets` WHERE `id` = ? AND `user_id` = ?';
  if (!req.user?.id) {
    res.status(401).json({ error: 'User not authenticated.' });
    return;
  }
  try {
    const values = [req.params.id, req.user.id];
    await pool.query(q, values);
    res.status(200).json({ message: 'Snippet deleted successfully.' });
  } catch (error) {
    console.error('SQL error:', error);
    res.status(500).json({ error: 'Something went wrong with the database.' });
  }
};

export { handleCreate, handleDelete, handleGetPage, handleModify, handleGetById, handleGetSnippetsByIDS };
