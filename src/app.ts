import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
// import userRouter from './routers/userRouter';


dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  console.log(req.method);
  res.send('This is the backend server of BloodBuddy, Whatsup visitor!!');
});

// app.use('/api/users', userRouter);
 

const PORT = parseInt(process.env.PORT as string, 10) || 3000;
const HOST = '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`Server is running at http://${HOST}:${PORT}`);
});