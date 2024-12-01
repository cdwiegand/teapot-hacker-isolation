package teapot_hacker_isolation

import (
	"context"
	"strconv"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type RedisStorage struct {
	IStorage

	config       RedisStorageConfig
	redisOptions *redis.Options
	redisConn    *redis.Client
}

type RedisStorageConfig struct {
	RedisServer string `json:"server"`
}

func NewRedisStorage(config RedisStorageConfig) (*RedisStorage, error) {
	opt, err := redis.ParseURL(config.RedisServer)
	if err != nil {
		return nil, err
	}

	redisConn := redis.NewClient(opt)

	return &RedisStorage{
		config:       config,
		redisOptions: opt,
		redisConn:    redisConn,
	}, nil
}

func (r *RedisStorage) GetIpViolations(ip string) (int, error) {
	ctx := context.Background()
	var foundI int
	found, err := r.redisConn.Get(ctx, "ip:"+ip).Result()
	if err == nil {
		foundI, err = strconv.Atoi(found)
	}
	return foundI, err
}

func (r *RedisStorage) IncrIpViolations(ip string, jailTime time.Duration) (int, error) {
	ctx := context.Background()
	newVal, err := r.redisConn.Incr(ctx, "ip:"+ip).Result()
	if err == nil {
		r.redisConn.Expire(ctx, "ip:"+ip, jailTime)
	}
	return int(newVal), err
}
