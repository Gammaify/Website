export default defineEventHandler(async (event) => {
    const db = hubDatabase();
    const { results } = await db.prepare('SELECT * FROM contact_us').all()

  return results
})