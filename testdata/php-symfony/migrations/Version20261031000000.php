<?php

namespace DoctrineMigrations;

final class Version20261031000000
{
    public function up(): string
    {
        return 'ALTER TABLE payment ADD captured_at DATETIME';
    }
}
