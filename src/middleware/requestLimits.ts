
/*
Summary: This file contains the ruls for reading
incoming data. If the data is bigger than 1MB, it will return
a 413 error. Else, it will continue to the next middleware.
*/
//holds rules for reading incoming data
export const bodyParserConfig = {
  json: {
    limit: '1mb',
    strict: true,
  },
  //only accept JSON data if it's smaller than 1MB
  urlencoded: {
    limit: '1mb',
    extended: true,
    parameterLimit: 100,
  },
};

import type { Request, Response, NextFunction } from 'express';

const MAX_CONTENT_LENGTH_BYTES = 1024 * 1024; // 1MB

export const requestSizeLimiter = (req: Request, res: Response, next: NextFunction) => {
  const contentLength = req.get('content-length');

  if (contentLength) {
    const size = parseInt(contentLength, 10);
    //if the size is greater than 1MB, return a 413 error
    //413 error: "too big", sends back a message explaining why
    if (!Number.isNaN(size) && size > MAX_CONTENT_LENGTH_BYTES) {
      return res.status(413).json({
        success: false,
        message: 'Request entity too large',
        maxSize: `${MAX_CONTENT_LENGTH_BYTES / 1024}KB`,
      });
    }
  }

  next();
};