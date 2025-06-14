import { db } from '../index.js';

after(done => {
  db.close(done);
});
