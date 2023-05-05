<?php

namespace KeycloakAuthGuard\Tests\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Str;
use KeycloakAuthGuard\Tests\Models\User;

class UserFactory extends Factory
{
    protected $model = User::class;

    public final const ESTONIAN_PIC_EXAMPLES = [
        '47607239590',
        '60505059544',
        '38804045250',
        '49511044258',
        '61912049562',
        '35307284287',
        '61911182720',
        '34509144746',
        '50608024740',
        '43912095240',
        '33904113735',
        '34507013712',
        '61607075277',
        '48110193735',
        '60902195205',
        '43602275770',
        '34911206063',
        '33408242792',
        '50301024958',
        '43410212286',
        '36010273790',
        '36610200191',
        '47012094714',
        '62207160033',
        '47507130084',
        '61408270284',
        '38104136520',
        '47109194242',
        '51309160119',
        '43503304242',
        '61501250086',
        '49311255780',
        '44509067055',
        '50211093727',
        '49406184952',
        '43610284763',
        '33811094234',
        '44208104267',
        '32505260024',
        '50401080067',
        '44809060035',
        '48609126030',
        '60409012227',
        '47103125760',
    ];

    public function definition()
    {
        return [
            'id' => Str::uuid()->toString(),
            'forename' => $this->faker->userName,
            'surname' => $this->faker->userName,
            'personal_identification_code' => $this->faker->randomElement(self::ESTONIAN_PIC_EXAMPLES),
        ];
    }
}
