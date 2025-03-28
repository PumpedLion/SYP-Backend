import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import userRouter from './routers/userRoutes';


dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  console.log(req.method);
  res.send('This is the backend server of MedLife!!');
});

app.use('/api/users', userRouter);
 


const PORT = 8000;
const HOST = "localhost"; // Change from "0.0.0.0" to "localhost"

app.listen(PORT, HOST, () => {
  console.log(`Server is running at http://${HOST}:${PORT}`);
});
