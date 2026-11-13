/* * Protocolo de Brana de Diamante V6.0
 * * Autor: Claudio Luis Manassero (ORCID: 0009-0009-6184-7858)
 * * Licencia: Creative Commons Atribucion-NoComercial-CompartirIgual 4.0 Internacional (CC BY-NC-SA 4.0)
 * * AVISO LEGAL: Se autoriza el uso personal, academico y de investigacion.
 * * Queda prohibida cualquier explotacion comercial, integracion en software propietario
 * * o uso por parte de entidades gubernamentales/industriales sin la autorizacion
 * * expresa del autor y la firma del correspondiente convenio de transferencia tecnologica.
 */


#ifndef BRANA_POOL_HPP
#define BRANA_POOL_HPP

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>

struct ThreadPool {
    std::vector<std::thread> trabajadores;
    std::queue<std::function<void()>> tareas;
    std::mutex queue_mutex;
    std::condition_variable cv_tarea;
    std::condition_variable cv_idle;
    bool stop = false;
    size_t en_vuelo = 0;

    void inicializar(size_t n_hilos)
    {
        if (!trabajadores.empty())
            return;
        stop = false;
        en_vuelo = 0;
        for (size_t i = 0; i < n_hilos; ++i)
        {
            trabajadores.emplace_back([this] {
                for (;;)
                {
                    std::function<void()> tarea;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->cv_tarea.wait(lock, [this] {
                            return this->stop || !this->tareas.empty();
                        });
                        if (this->stop && this->tareas.empty())
                            return;
                        tarea = std::move(this->tareas.front());
                        this->tareas.pop();
                    }
                    tarea();
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        if (this->en_vuelo > 0)
                            --this->en_vuelo;
                        if (this->en_vuelo == 0 && this->tareas.empty())
                            this->cv_idle.notify_all();
                    }
                }
            });
        }
    }

    void encolar(std::function<void()> f)
    {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tareas.push(std::move(f));
            ++en_vuelo;
        }
        cv_tarea.notify_one();
    }

    void esperar_tareas()
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        cv_idle.wait(lock, [this] {
            return this->tareas.empty() && this->en_vuelo == 0;
        });
    }

    void cerrar()
    {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        cv_tarea.notify_all();
        for (std::thread &t : trabajadores)
        {
            if (t.joinable())
                t.join();
        }
        trabajadores.clear();
    }

    ~ThreadPool()
    {
        if (!trabajadores.empty())
            cerrar();
    }
};

#endif
