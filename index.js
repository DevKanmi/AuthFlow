import { app } from "./app.js"
import { PORT } from "./envVariables.js"
import { DBConnection } from "./configs/db.js"
import logger from "./utils/logger.js"

app.listen(PORT, () => {
  DBConnection()
  logger.info(`Server running on port http://localhost:${PORT}`)
})