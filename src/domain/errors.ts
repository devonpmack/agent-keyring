// Errors whose message is safe to show to the caller. Anything else becomes a
// generic 500 with a request ID, so internal details (and values) never leak.
export class AppError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export const notFound = (what = 'Not found') => new AppError('not_found', what, 404);
export const forbidden = (what = 'Forbidden') => new AppError('forbidden', what, 403);
