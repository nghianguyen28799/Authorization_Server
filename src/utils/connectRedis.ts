import { createClient } from 'redis';

require("dotenv").config();

const redisUrl = process.env.REDIS_URL;

const redisClient = createClient({
    url: redisUrl,
});

const connectRedis = async () => {
    try {
        await redisClient.connect();
        console.log('Redis client connect successfully');
        redisClient.set('try', 'Hello Welcome to Express with TypeORM');
    } catch (error) {
        setTimeout(connectRedis, 5000);
    }
};

connectRedis();

export default redisClient;
